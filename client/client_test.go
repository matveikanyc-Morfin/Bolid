package client_test

import (
	"bytes"
	"io"
	"testing"
	"time"

	"mirage/client"
	"mirage/internal/crypto"
	"mirage/internal/session"
	"mirage/internal/transport"
)

// mockTun — поддельное TUN-устройство на каналах (тест без ОС).
type mockTun struct {
	out  chan []byte
	in   chan []byte
	done chan struct{}
}

func newMockTun() *mockTun {
	return &mockTun{out: make(chan []byte, 8), in: make(chan []byte, 8), done: make(chan struct{})}
}

func (m *mockTun) Name() string { return "mock" }
func (m *mockTun) MTU() int     { return 1380 }
func (m *mockTun) ReadPacket(buf []byte) (int, error) {
	select {
	case p := <-m.out:
		return copy(buf, p), nil
	case <-m.done:
		return 0, io.EOF
	}
}
func (m *mockTun) WritePacket(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	select {
	case m.in <- cp:
	case <-m.done:
	}
	return len(p), nil
}
func (m *mockTun) Close() error {
	select {
	case <-m.done:
	default:
		close(m.done)
	}
	return nil
}

// startDemux поднимает демукс-сервер по UDP: принимает рукопожатия в любой
// момент, отражает RecordData и отвечает на keepalive. Если addr == "" —
// случайный порт. Возвращает адрес и функцию остановки.
func startDemux(t *testing.T, sStatic crypto.Keypair, addr string) (string, func()) {
	t.Helper()
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	srv, err := transport.ListenUDP(addr)
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	done := make(chan struct{})
	go func() {
		var cur *session.Session
		for {
			pkt, err := srv.Recv()
			if err != nil {
				return
			}
			if len(pkt) == 0 {
				continue
			}
			if pkt[0] == session.MsgHandshakeInit {
				hs, err := session.NewHandshake(session.Config{
					Initiator: false, Static: sStatic,
					LocalIndex: 0xB2B2B2B2, Prologue: crypto.Prologue(),
				})
				if err != nil {
					continue
				}
				if _, _, err := hs.FramedRead(pkt); err != nil {
					continue
				}
				m2, sess, err := hs.FramedWrite(nil)
				if err != nil || sess == nil {
					continue
				}
				_ = srv.Send(m2)
				cur = sess
				continue
			}
			if cur == nil {
				continue
			}
			typ, pl, err := cur.Open(pkt)
			if err != nil {
				continue
			}
			switch typ {
			case session.RecordData:
				if rec, err := cur.Seal(session.RecordData, pl); err == nil {
					_ = srv.Send(rec)
				}
			case session.RecordKeepalive:
				if rec, err := cur.Seal(session.RecordKeepalive, nil); err == nil {
					_ = srv.Send(rec)
				}
			}
		}
	}()
	stop := func() {
		close(done)
		srv.Close()
	}
	return srv.LocalAddr(), stop
}

func dialer(addr string) client.Dialer {
	return func() (transport.Conn, error) {
		c, err := transport.DialUDP(addr)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
}

func newClient(t *testing.T, addr string, cStatic, sStatic crypto.Keypair, kaSec, idleSec int) *client.Client {
	t.Helper()
	c, err := client.New(client.Config{
		ServerPub:    sStatic.Public,
		PrivateKey:   cStatic.Private,
		MTU:          1380,
		KeepaliveSec: kaSec,
		IdleSec:      idleSec,
		Dial:         dialer(addr),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestClientLibraryRoundtrip(t *testing.T) {
	cStatic, _ := crypto.GenerateKeypair()
	sStatic, _ := crypto.GenerateKeypair()
	addr, stop := startDemux(t, sStatic, "")
	defer stop()

	c := newClient(t, addr, cStatic, sStatic, 1, 3)
	dev := newMockTun()
	go func() { _ = c.Run(dev) }()
	defer c.Stop()
	defer dev.Close()

	packet := []byte("псевдо-IP-пакет через библиотеку MIRAGE")
	if !roundtrip(dev, packet, 4*time.Second) {
		t.Fatal("пакет не вернулся через туннель")
	}
}

func TestClientStop(t *testing.T) {
	cStatic, _ := crypto.GenerateKeypair()
	sStatic, _ := crypto.GenerateKeypair()
	addr, stop := startDemux(t, sStatic, "")
	defer stop()

	c := newClient(t, addr, cStatic, sStatic, 1, 3)
	dev := newMockTun()
	done := make(chan struct{})
	go func() { _ = c.Run(dev); close(done) }()

	// дождаться установления
	roundtrip(dev, []byte("hi"), 4*time.Second)

	c.Stop()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run не завершился после Stop")
	}
}

// TestClientReconnect — обрыв и рестарт сервера: клиент должен сам переподключиться.
func TestClientReconnect(t *testing.T) {
	cStatic, _ := crypto.GenerateKeypair()
	sStatic, _ := crypto.GenerateKeypair()

	addr, stop1 := startDemux(t, sStatic, "")

	c := newClient(t, addr, cStatic, sStatic, 1, 2) // быстрый keepalive/idle для теста
	dev := newMockTun()
	go func() { _ = c.Run(dev) }()
	defer c.Stop()
	defer dev.Close()

	if !roundtrip(dev, []byte("before"), 5*time.Second) {
		t.Fatal("первичное подключение не работает")
	}

	// «Обрыв»: останавливаем сервер.
	stop1()
	time.Sleep(500 * time.Millisecond)

	// Сервер возвращается на ТОМ ЖЕ адресе (имитация восстановления сети/рестарта).
	_, stop2 := startDemux(t, sStatic, addr)
	defer stop2()

	// Клиент должен сам переподключиться (re-handshake) и снова прокачивать трафик.
	if !roundtrip(dev, []byte("after-reconnect"), 15*time.Second) {
		t.Fatal("клиент не переподключился после рестарта сервера")
	}
}

// roundtrip многократно шлёт пакет в TUN и ждёт его возврата (эхо сервера) до
// дедлайна. Пакеты, отправленные пока туннель не подключён, отбрасываются —
// поэтому шлём повторно.
func roundtrip(dev *mockTun, packet []byte, timeout time.Duration) bool {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	send := time.NewTicker(300 * time.Millisecond)
	defer send.Stop()

	// первая отправка сразу
	select {
	case dev.out <- packet:
	default:
	}
	for {
		select {
		case got := <-dev.in:
			if bytes.Equal(got, packet) {
				return true
			}
		case <-send.C:
			select {
			case dev.out <- packet:
			default:
			}
		case <-deadline.C:
			return false
		}
	}
}
