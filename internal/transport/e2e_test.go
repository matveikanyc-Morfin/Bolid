package transport_test

import (
	"bytes"
	"sync"
	"testing"

	"mirage/internal/crypto"
	"mirage/internal/session"
	"mirage/internal/transport"
)

// TestSessionOverUDP — главный e2e Фазы 1: две стороны проходят полное
// рукопожатие Noise_IK поверх реального UDP-сокета (loopback) и обмениваются
// зашифрованными записями в обе стороны.
func TestSessionOverUDP(t *testing.T) {
	cStatic, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sStatic, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	srv, err := transport.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srv.Close()
	addr := srv.LocalAddr()

	type result struct {
		sess *session.Session
		err  error
	}
	srvCh := make(chan result, 1)

	// Сервер (responder) в отдельной горутине.
	go func() {
		hs, err := session.NewHandshake(session.Config{
			Initiator:  false,
			Static:     sStatic,
			LocalIndex: 0xB2B2B2B2,
			Prologue:   crypto.Prologue(),
		})
		if err != nil {
			srvCh <- result{nil, err}
			return
		}
		m1, err := srv.Recv()
		if err != nil {
			srvCh <- result{nil, err}
			return
		}
		if _, _, err := hs.FramedRead(m1); err != nil {
			srvCh <- result{nil, err}
			return
		}
		m2, sess, err := hs.FramedWrite(nil)
		if err != nil {
			srvCh <- result{nil, err}
			return
		}
		if err := srv.Send(m2); err != nil {
			srvCh <- result{nil, err}
			return
		}
		srvCh <- result{sess, nil}
	}()

	// Клиент (initiator).
	cli, err := transport.DialUDP(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()

	cHS, err := session.NewHandshake(session.Config{
		Initiator:  true,
		Static:     cStatic,
		PeerStatic: sStatic.Public,
		LocalIndex: 0xA1A1A1A1,
		Prologue:   crypto.Prologue(),
	})
	if err != nil {
		t.Fatal(err)
	}

	m1, _, err := cHS.FramedWrite(nil)
	if err != nil {
		t.Fatalf("msg1: %v", err)
	}
	if err := cli.Send(m1); err != nil {
		t.Fatalf("send msg1: %v", err)
	}
	m2, err := cli.Recv()
	if err != nil {
		t.Fatalf("recv msg2: %v", err)
	}
	_, cSess, err := cHS.FramedRead(m2)
	if err != nil {
		t.Fatalf("read msg2: %v", err)
	}
	if cSess == nil {
		t.Fatal("клиент не получил сессию")
	}

	srvRes := <-srvCh
	if srvRes.err != nil {
		t.Fatalf("сервер: %v", srvRes.err)
	}
	sSess := srvRes.sess

	// Данные: client -> server.
	plain := []byte("трафик через UDP-туннель MIRAGE")
	rec, err := cSess.Seal(session.RecordData, plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := cli.Send(rec); err != nil {
		t.Fatalf("send rec: %v", err)
	}
	inRec, err := srv.Recv()
	if err != nil {
		t.Fatalf("srv recv rec: %v", err)
	}
	typ, got, err := sSess.Open(inRec)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if typ != session.RecordData || !bytes.Equal(got, plain) {
		t.Fatalf("сервер расшифровал неверно: %q", got)
	}

	// Эхо: server -> client.
	echo, err := sSess.Seal(session.RecordData, got)
	if err != nil {
		t.Fatalf("seal echo: %v", err)
	}
	if err := srv.Send(echo); err != nil {
		t.Fatalf("send echo: %v", err)
	}
	backRec, err := cli.Recv()
	if err != nil {
		t.Fatalf("cli recv echo: %v", err)
	}
	_, back, err := cSess.Open(backRec)
	if err != nil {
		t.Fatalf("open echo: %v", err)
	}
	if !bytes.Equal(back, plain) {
		t.Fatalf("эхо не совпало: %q", back)
	}
}

// establishMem проводит рукопожатие в памяти и возвращает обе сессии.
func establishMem(t *testing.T) (cSess, sSess *session.Session) {
	t.Helper()
	cStatic, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sStatic, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cHS, err := session.NewHandshake(session.Config{
		Initiator: true, Static: cStatic, PeerStatic: sStatic.Public,
		LocalIndex: 0xA1A1A1A1, Prologue: crypto.Prologue(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sHS, err := session.NewHandshake(session.Config{
		Initiator: false, Static: sStatic,
		LocalIndex: 0xB2B2B2B2, Prologue: crypto.Prologue(),
	})
	if err != nil {
		t.Fatal(err)
	}
	m1, _, err := cHS.FramedWrite(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sHS.FramedRead(m1); err != nil {
		t.Fatal(err)
	}
	m2, ss, err := sHS.FramedWrite(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, cs, err := cHS.FramedRead(m2)
	if err != nil {
		t.Fatal(err)
	}
	return cs, ss
}

// TestConcurrentBidirectionalRace воспроизводит конкурентную модель data-path
// туннеля: на одной сессии Seal вызывается из одной горутины, а Open — из
// другой (оба направления одновременно). Запускать с -race.
func TestConcurrentBidirectionalRace(t *testing.T) {
	cSess, sSess := establishMem(t)
	const N = 500

	ch1 := make(chan []byte, 64) // client -> server
	ch2 := make(chan []byte, 64) // server -> client
	var wg sync.WaitGroup
	wg.Add(4)

	// client запечатывает (мутирует send-состояние client-сессии)
	go func() {
		defer wg.Done()
		defer close(ch1)
		for i := 0; i < N; i++ {
			rec, err := cSess.Seal(session.RecordData, []byte{byte(i)})
			if err != nil {
				t.Errorf("client seal: %v", err)
				return
			}
			ch1 <- rec
		}
	}()
	// server расшифровывает
	go func() {
		defer wg.Done()
		n := 0
		for rec := range ch1 {
			if _, _, err := sSess.Open(rec); err != nil {
				t.Errorf("server open: %v", err)
				return
			}
			n++
		}
		if n != N {
			t.Errorf("сервер принял %d из %d", n, N)
		}
	}()
	// server запечатывает (одновременно с server open выше — разные поля сессии)
	go func() {
		defer wg.Done()
		defer close(ch2)
		for i := 0; i < N; i++ {
			rec, err := sSess.Seal(session.RecordData, []byte{byte(i)})
			if err != nil {
				t.Errorf("server seal: %v", err)
				return
			}
			ch2 <- rec
		}
	}()
	// client расшифровывает (одновременно с client seal)
	go func() {
		defer wg.Done()
		n := 0
		for rec := range ch2 {
			if _, _, err := cSess.Open(rec); err != nil {
				t.Errorf("client open: %v", err)
				return
			}
			n++
		}
		if n != N {
			t.Errorf("клиент принял %d из %d", n, N)
		}
	}()

	wg.Wait()
}
