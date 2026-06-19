package server_test

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"mirage/internal/crypto"
	"mirage/internal/session"
	"mirage/internal/transport"
	"mirage/server"
)

type mockTun struct {
	out  chan []byte
	in   chan []byte
	done chan struct{}
}

func newMockTun() *mockTun {
	return &mockTun{out: make(chan []byte, 16), in: make(chan []byte, 16), done: make(chan struct{})}
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
func (m *mockTun) Close() error { close(m.done); return nil }

// clientConnect делает рукопожатие клиента и возвращает соединение и сессию.
func clientConnect(t *testing.T, addr string, cStatic, sStatic crypto.Keypair) (*transport.UDPClient, *session.Session) {
	t.Helper()
	conn, err := transport.DialUDP(addr)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := session.NewHandshake(session.Config{
		Initiator: true, Static: cStatic, PeerStatic: sStatic.Public,
		LocalIndex: 0xAAAA0001, Prologue: crypto.Prologue(),
	})
	if err != nil {
		t.Fatal(err)
	}
	m1, _, err := hs.FramedWrite(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Send(m1); err != nil {
		t.Fatal(err)
	}
	m2, err := recvTimeout(conn, 3*time.Second)
	if err != nil {
		t.Fatalf("нет ответа сервера на рукопожатие: %v", err)
	}
	_, sess, err := hs.FramedRead(m2)
	if err != nil {
		t.Fatalf("FramedRead: %v", err)
	}
	if sess == nil {
		t.Fatal("сессия не установлена")
	}
	return conn, sess
}

func recvTimeout(conn *transport.UDPClient, d time.Duration) ([]byte, error) {
	type r struct {
		b []byte
		e error
	}
	ch := make(chan r, 1)
	go func() { b, e := conn.Recv(); ch <- r{b, e} }()
	select {
	case x := <-ch:
		return x.b, x.e
	case <-time.After(d):
		return nil, errors.New("timeout")
	}
}

func ipv4To(dst netip.Addr, marker byte) []byte {
	p := make([]byte, 20)
	p[0] = 0x45 // version 4, IHL 5
	p[10] = marker
	d := dst.As4()
	copy(p[16:20], d[:])
	return p
}

func TestMultiPeerRouting(t *testing.T) {
	sStatic, _ := crypto.GenerateKeypair()
	c1, _ := crypto.GenerateKeypair()
	c2, _ := crypto.GenerateKeypair()

	ip1 := netip.MustParseAddr("10.7.0.2")
	ip2 := netip.MustParseAddr("10.7.0.3")

	srv, err := server.New(sStatic.Private, []server.Peer{
		{PublicKey: c1.Public, TunnelIP: ip1, Name: "c1"},
		{PublicKey: c2.Public, TunnelIP: ip2, Name: "c2"},
	})
	if err != nil {
		t.Fatal(err)
	}

	udp, err := transport.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dev := newMockTun()
	go func() { _ = srv.Serve(udp, dev) }()
	defer srv.Stop()
	defer dev.Close()
	addr := udp.LocalAddr()

	conn1, sess1 := clientConnect(t, addr, c1, sStatic)
	defer conn1.Close()
	conn2, sess2 := clientConnect(t, addr, c2, sStatic)
	defer conn2.Close()

	// --- Входящее: client1 шлёт запись → сервер пишет в TUN ---
	payload := []byte("пакет от client1")
	rec, _ := sess1.Seal(session.RecordData, payload)
	if err := conn1.Send(rec); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-dev.in:
		if !bytes.Equal(got, payload) {
			t.Fatalf("сервер записал в TUN не то: %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("сервер не записал пакет client1 в TUN")
	}

	// --- Исходящее: пакет из TUN на 10.7.0.2 → должен прийти client1 ---
	pkt1 := ipv4To(ip1, 0x11)
	dev.out <- pkt1
	if got, err := recvTimeout(conn1, 3*time.Second); err != nil {
		t.Fatalf("client1 не получил свой пакет: %v", err)
	} else if _, pl, e := sess1.Open(got); e != nil || !bytes.Equal(pl, pkt1) {
		t.Fatalf("client1 получил не тот пакет (err=%v)", e)
	}

	// --- Исходящее: пакет на 10.7.0.3 → должен прийти client2 ---
	pkt2 := ipv4To(ip2, 0x22)
	dev.out <- pkt2
	if got, err := recvTimeout(conn2, 3*time.Second); err != nil {
		t.Fatalf("client2 не получил свой пакет: %v", err)
	} else if _, pl, e := sess2.Open(got); e != nil || !bytes.Equal(pl, pkt2) {
		t.Fatalf("client2 получил не тот пакет (err=%v)", e)
	}

	// --- Пакет на неизвестный адрес 10.7.0.99 → отбрасывается ---
	dev.out <- ipv4To(netip.MustParseAddr("10.7.0.99"), 0x99)
	if _, err := recvTimeout(conn1, 800*time.Millisecond); err == nil {
		t.Fatal("client1 не должен получать пакет для чужого адреса")
	}
}

func TestUnknownPeerRejected(t *testing.T) {
	sStatic, _ := crypto.GenerateKeypair()
	known, _ := crypto.GenerateKeypair()
	stranger, _ := crypto.GenerateKeypair() // не в реестре

	srv, err := server.New(sStatic.Private, []server.Peer{
		{PublicKey: known.Public, TunnelIP: netip.MustParseAddr("10.7.0.2"), Name: "known"},
	})
	if err != nil {
		t.Fatal(err)
	}
	udp, err := transport.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dev := newMockTun()
	go func() { _ = srv.Serve(udp, dev) }()
	defer srv.Stop()
	defer dev.Close()
	addr := udp.LocalAddr()

	conn, err := transport.DialUDP(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	hs, _ := session.NewHandshake(session.Config{
		Initiator: true, Static: stranger, PeerStatic: sStatic.Public,
		LocalIndex: 1, Prologue: crypto.Prologue(),
	})
	m1, _, _ := hs.FramedWrite(nil)
	_ = conn.Send(m1)
	// Сервер не должен ответить неизвестному ключу (anti-probe).
	if _, err := recvTimeout(conn, 1*time.Second); err == nil {
		t.Fatal("сервер ответил неизвестному клиенту — должен молчать")
	}
}
