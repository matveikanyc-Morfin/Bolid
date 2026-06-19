package main

import (
	"fmt"
	"sync"

	"mirage/internal/crypto"
	"mirage/internal/session"
	"mirage/internal/transport"
	"mirage/internal/tun"
)

// serverTunnel — серверный data-path с демультиплексированием. В отличие от
// клиента, сервер слушает один UDP-сокет, по которому приходят и рукопожатия, и
// данные. Первый байт пакета классифицирует его:
//
//	MsgHandshakeInit → (пере)установить сессию, ответить MsgHandshakeResp;
//	иначе            → транспортная запись текущей сессии.
//
// Это позволяет клиенту переподключаться в любой момент (новое рукопожатие
// заменяет активную сессию) — основа стабильности.
type serverTunnel struct {
	static crypto.Keypair
	srv    *transport.UDPServer
	dev    tun.Device

	mu      sync.RWMutex
	current *session.Session

	sendMu sync.Mutex // сериализует Seal+Send (Seal мутирует состояние сессии)
}

func (s *serverTunnel) currentSession() *session.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// send запечатывает и отправляет запись текущей сессии (потокобезопасно).
func (s *serverTunnel) send(typ byte, payload []byte) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	sess := s.currentSession()
	if sess == nil {
		return
	}
	if rec, err := sess.Seal(typ, payload); err == nil {
		_ = s.srv.Send(rec)
	}
}

// runServerTunnel запускает серверный туннель до фатальной ошибки.
func runServerTunnel(static crypto.Keypair, srv *transport.UDPServer, dev tun.Device) error {
	st := &serverTunnel{static: static, srv: srv, dev: dev}
	errc := make(chan error, 2)

	// TUN → сеть (использует текущую сессию; если её нет — пакет отбрасывается).
	go func() {
		buf := make([]byte, dev.MTU()+128)
		for {
			n, err := dev.ReadPacket(buf)
			if err != nil {
				errc <- fmt.Errorf("чтение TUN: %w", err)
				return
			}
			if n == 0 {
				continue
			}
			st.send(session.RecordData, buf[:n])
		}
	}()

	// Сеть → демультиплексор.
	go func() {
		for {
			pkt, err := srv.Recv()
			if err != nil {
				errc <- fmt.Errorf("приём из сети: %w", err)
				return
			}
			if len(pkt) == 0 {
				continue
			}
			if pkt[0] == session.MsgHandshakeInit {
				st.handleHandshake(pkt)
				continue
			}
			// Транспортная запись.
			sess := st.currentSession()
			if sess == nil {
				continue
			}
			typ, pl, err := sess.Open(pkt)
			if err != nil {
				continue // битый/повтор/чужой
			}
			switch typ {
			case session.RecordData:
				if _, err := dev.WritePacket(pl); err != nil {
					errc <- fmt.Errorf("запись в TUN: %w", err)
					return
				}
			case session.RecordKeepalive:
				st.send(session.RecordKeepalive, nil) // ответ → клиент видит живость линка
			case session.RecordRoamProbe, session.RecordClose:
				// служебные — игнорируем (CLOSE не рвём, ждём новое рукопожатие)
			}
		}
	}()

	return <-errc
}

// handleHandshake обрабатывает входящее MsgHandshakeInit: проводит сторону
// респондента и заменяет активную сессию.
func (s *serverTunnel) handleHandshake(pkt []byte) {
	hs, err := session.NewHandshake(session.Config{
		Initiator:  false,
		Static:     s.static,
		LocalIndex: randIndex(),
		Prologue:   crypto.Prologue(),
	})
	if err != nil {
		return
	}
	if _, _, err := hs.FramedRead(pkt); err != nil {
		return // не наш клиент / битое рукопожатие — молча игнорируем
	}
	m2, sess, err := hs.FramedWrite(nil)
	if err != nil || sess == nil {
		return
	}
	if err := s.srv.Send(m2); err != nil {
		return
	}
	s.mu.Lock()
	s.current = sess
	s.mu.Unlock()
	fmt.Println("[server] сессия установлена (клиент подключился)")
}

// --- TLS-транспорт (профиль tls-reality, шаг 3a) ---
//
// В отличие от UDP, TLS даёт по соединению на клиента. Поддерживаем один активный
// туннель: новое соединение становится активным, предыдущее закрывается
// (переподключение). Один постоянный читатель TUN отправляет в активную сессию.

type tlsServerTunnel struct {
	static crypto.Keypair
	dev    tun.Device

	mu     sync.RWMutex
	conn   transport.Conn
	sess   *session.Session
	sendMu sync.Mutex // сериализует Seal+Send
}

func (t *tlsServerTunnel) current() (transport.Conn, *session.Session) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.conn, t.sess
}

func (t *tlsServerTunnel) setActive(conn transport.Conn, sess *session.Session) {
	t.mu.Lock()
	prev := t.conn
	t.conn, t.sess = conn, sess
	t.mu.Unlock()
	if prev != nil && prev != conn {
		prev.Close() // вытесняем предыдущего клиента
	}
}

func (t *tlsServerTunnel) clearIf(conn transport.Conn) {
	t.mu.Lock()
	if t.conn == conn {
		t.conn, t.sess = nil, nil
	}
	t.mu.Unlock()
}

// send запечатывает и отправляет запись по заданному соединению/сессии.
func (t *tlsServerTunnel) send(conn transport.Conn, sess *session.Session, typ byte, payload []byte) {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	if rec, err := sess.Seal(typ, payload); err == nil {
		_ = conn.Send(rec)
	}
}

// runServerTunnelTLS обслуживает TLS-туннель. accept абстрагирует листенер
// (чтобы tunnel.go не зависел от пакета обфускации).
func runServerTunnelTLS(static crypto.Keypair, accept func() (transport.Conn, error), dev tun.Device) error {
	t := &tlsServerTunnel{static: static, dev: dev}

	// TUN → активная сессия.
	go func() {
		buf := make([]byte, dev.MTU()+128)
		for {
			n, err := dev.ReadPacket(buf)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			conn, sess := t.current()
			if sess == nil {
				continue
			}
			t.send(conn, sess, session.RecordData, buf[:n])
		}
	}()

	for {
		conn, err := accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go t.handleConn(conn)
	}
}

func (t *tlsServerTunnel) handleConn(conn transport.Conn) {
	defer conn.Close()

	hs, err := session.NewHandshake(session.Config{
		Initiator:  false,
		Static:     t.static,
		LocalIndex: randIndex(),
		Prologue:   crypto.Prologue(),
	})
	if err != nil {
		return
	}
	m1, err := conn.Recv()
	if err != nil {
		return
	}
	if _, _, err := hs.FramedRead(m1); err != nil {
		return // не наш клиент — закрываем (3b добавит релей на приманку)
	}
	m2, sess, err := hs.FramedWrite(nil)
	if err != nil || sess == nil {
		return
	}
	if err := conn.Send(m2); err != nil {
		return
	}
	t.setActive(conn, sess)
	defer t.clearIf(conn)
	fmt.Println("[server] клиент подключился (TLS)")

	// Сеть → TUN для этого соединения.
	for {
		rec, err := conn.Recv()
		if err != nil {
			return
		}
		typ, pl, err := sess.Open(rec)
		if err != nil {
			continue
		}
		switch typ {
		case session.RecordData:
			if _, err := t.dev.WritePacket(pl); err != nil {
				return
			}
		case session.RecordKeepalive:
			t.send(conn, sess, session.RecordKeepalive, nil) // ответ на keepalive
		case session.RecordRoamProbe, session.RecordClose:
		}
	}
}
