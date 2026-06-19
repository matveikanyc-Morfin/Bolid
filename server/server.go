// Package server — multi-peer сервер MIRAGE.
//
// Один UDP-сокет обслуживает много клиентов одновременно. Клиент
// аутентифицируется по своему статическому ключу (Noise_IK раскрывает его в
// рукопожатии); неизвестные ключи отбрасываются молча (anti-probe). Маршрутизация:
//
//   - входящие записи → по session_id выбираем сессию пира, расшифровываем,
//     пишем IP-пакет в общий TUN (далее ядро NAT-ит в интернет);
//   - пакеты из TUN → по адресу назначения находим пира (allowed-IP),
//     шифруем его сессией и шлём на его текущий endpoint (с роумингом).
package server

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"mirage/internal/crypto"
	"mirage/internal/session"
	"mirage/internal/tun"
)

// PacketConn — UDP-сокет с явным адресом источника (реализует transport.UDPServer).
type PacketConn interface {
	RecvFrom() ([]byte, netip.AddrPort, error)
	SendTo([]byte, netip.AddrPort) error
	Close() error
}

// Peer — разрешённый клиент: его публичный ключ и адрес в туннеле.
type Peer struct {
	PublicKey []byte
	TunnelIP  netip.Addr
	Name      string
}

// Server — multi-peer сервер.
type Server struct {
	static     crypto.Keypair
	peersByKey map[string]*Peer

	conn PacketConn
	dev  tun.Device

	mu     sync.RWMutex
	byID   map[uint32]*peerSession  // session_id → сессия
	byIP   map[netip.Addr]*peerSession
	byPeer map[string]*peerSession // pubkey → текущая сессия (для вытеснения старой)

	sendMu sync.Mutex
	stop   chan struct{}
	once   sync.Once
}

type peerSession struct {
	id   uint32
	sess *session.Session
	peer *Peer
	ep   atomic.Pointer[netip.AddrPort] // текущий endpoint клиента (роуминг)
}

// New создаёт сервер с приватным ключом и списком разрешённых пиров.
func New(privateKey []byte, peers []Peer) (*Server, error) {
	static, err := crypto.KeypairFromPrivate(privateKey)
	if err != nil {
		return nil, fmt.Errorf("server: приватный ключ: %w", err)
	}
	byKey := make(map[string]*Peer, len(peers))
	for i := range peers {
		p := peers[i]
		if len(p.PublicKey) != crypto.KeyLen {
			return nil, fmt.Errorf("server: пир %q: неверный публичный ключ", p.Name)
		}
		if !p.TunnelIP.IsValid() {
			return nil, fmt.Errorf("server: пир %q: неверный TunnelIP", p.Name)
		}
		byKey[string(p.PublicKey)] = &p
	}
	return &Server{
		static:     static,
		peersByKey: byKey,
		byID:       make(map[uint32]*peerSession),
		byIP:       make(map[netip.Addr]*peerSession),
		byPeer:     make(map[string]*peerSession),
		stop:       make(chan struct{}),
	}, nil
}

func randIndex() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:])
}

// Serve обслуживает клиентов поверх conn и dev. Блокирует до ошибки/Stop.
func (s *Server) Serve(conn PacketConn, dev tun.Device) error {
	s.mu.Lock()
	s.conn = conn
	s.dev = dev
	s.mu.Unlock()
	go s.tunReader()

	for {
		pkt, src, err := conn.RecvFrom()
		if err != nil {
			select {
			case <-s.stop:
				return nil
			default:
				return fmt.Errorf("server: recv: %w", err)
			}
		}
		if len(pkt) == 0 {
			continue
		}
		if pkt[0] == session.MsgHandshakeInit {
			s.handleHandshake(pkt, src)
			continue
		}
		sid, ok := session.RecordSessionID(pkt)
		if !ok {
			continue
		}
		s.mu.RLock()
		ms := s.byID[sid]
		s.mu.RUnlock()
		if ms == nil {
			continue
		}
		typ, pl, err := ms.sess.Open(pkt)
		if err != nil {
			continue // битый/повтор/чужой
		}
		ms.ep.Store(&src) // роуминг: endpoint обновляем только после аутентификации
		switch typ {
		case session.RecordData:
			_, _ = s.dev.WritePacket(pl)
		case session.RecordKeepalive:
			s.sendTo(ms, session.RecordKeepalive, nil)
		}
	}
}

// Stop завершает работу сервера.
func (s *Server) Stop() {
	s.once.Do(func() {
		close(s.stop)
		s.mu.RLock()
		c := s.conn
		s.mu.RUnlock()
		if c != nil {
			c.Close()
		}
	})
}

// handleHandshake обрабатывает рукопожатие, аутентифицирует клиента по ключу и
// регистрирует/обновляет его сессию.
func (s *Server) handleHandshake(pkt []byte, src netip.AddrPort) {
	id := randIndex()
	hs, err := session.NewHandshake(session.Config{
		Initiator:  false,
		Static:     s.static,
		LocalIndex: id,
		Prologue:   crypto.Prologue(),
	})
	if err != nil {
		return
	}
	if _, _, err := hs.FramedRead(pkt); err != nil {
		return
	}
	clientPub := hs.PeerStatic()
	s.mu.RLock()
	peer := s.peersByKey[string(clientPub)]
	s.mu.RUnlock()
	if peer == nil {
		return // неизвестный клиент — молча отбрасываем (anti-probe)
	}
	m2, sess, err := hs.FramedWrite(nil)
	if err != nil || sess == nil {
		return
	}
	if err := s.conn.SendTo(m2, src); err != nil {
		return
	}

	ms := &peerSession{id: id, sess: sess, peer: peer}
	ms.ep.Store(&src)

	s.mu.Lock()
	if old := s.byPeer[string(clientPub)]; old != nil {
		delete(s.byID, old.id) // вытесняем прежнюю сессию этого пира
	}
	s.byID[id] = ms
	s.byIP[peer.TunnelIP] = ms
	s.byPeer[string(clientPub)] = ms
	s.mu.Unlock()
	fmt.Printf("[server] пир подключился: %s (%s)\n", peer.Name, peer.TunnelIP)
}

// tunReader читает TUN и маршрутизирует пакеты нужному пиру по адресу назначения.
func (s *Server) tunReader() {
	buf := make([]byte, s.dev.MTU()+128)
	for {
		n, err := s.dev.ReadPacket(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		dst, ok := destIP(buf[:n])
		if !ok {
			continue
		}
		s.mu.RLock()
		ms := s.byIP[dst]
		s.mu.RUnlock()
		if ms == nil {
			continue // нет пира для этого адреса — отбрасываем
		}
		s.sendTo(ms, session.RecordData, buf[:n])
	}
}

// sendTo шифрует и отправляет запись пиру на его текущий endpoint.
func (s *Server) sendTo(ms *peerSession, typ byte, payload []byte) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	ep := ms.ep.Load()
	if ep == nil {
		return
	}
	rec, err := ms.sess.Seal(typ, payload)
	if err != nil {
		return
	}
	_ = s.conn.SendTo(rec, *ep)
}

// destIP извлекает адрес назначения из IP-пакета (IPv4/IPv6).
func destIP(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(pkt[16:20])), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(pkt[24:40])), true
	default:
		return netip.Addr{}, false
	}
}
