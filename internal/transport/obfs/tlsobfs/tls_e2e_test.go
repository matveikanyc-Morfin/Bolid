package tlsobfs_test

import (
	"bytes"
	"testing"

	"mirage/internal/crypto"
	"mirage/internal/session"
	"mirage/internal/transport/obfs/tlsobfs"
)

// TestSessionOverTLS — главный e2e шага 3a: полное рукопожатие Noise_IK и обмен
// зашифрованными записями MIRAGE поверх НАСТОЯЩЕГО TLS 1.3 (loopback). Доказывает,
// что верхний стек работает внутри TLS без изменений.
func TestSessionOverTLS(t *testing.T) {
	cStatic, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sStatic, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tlsobfs.Listen("127.0.0.1:0", "www.example-cdn.com")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.LocalAddr()

	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()
		hs, err := session.NewHandshake(session.Config{
			Initiator: false, Static: sStatic,
			LocalIndex: 0xB2B2B2B2, Prologue: crypto.Prologue(),
		})
		if err != nil {
			srvErr <- err
			return
		}
		m1, err := conn.Recv()
		if err != nil {
			srvErr <- err
			return
		}
		if _, _, err := hs.FramedRead(m1); err != nil {
			srvErr <- err
			return
		}
		m2, sess, err := hs.FramedWrite(nil)
		if err != nil {
			srvErr <- err
			return
		}
		if err := conn.Send(m2); err != nil {
			srvErr <- err
			return
		}
		// эхо одной записи
		rec, err := conn.Recv()
		if err != nil {
			srvErr <- err
			return
		}
		_, pl, err := sess.Open(rec)
		if err != nil {
			srvErr <- err
			return
		}
		echo, err := sess.Seal(session.RecordData, pl)
		if err != nil {
			srvErr <- err
			return
		}
		srvErr <- conn.Send(echo)
	}()

	conn, err := tlsobfs.DialTLS(addr, "www.example-cdn.com")
	if err != nil {
		t.Fatalf("dial tls: %v", err)
	}
	defer conn.Close()

	cHS, err := session.NewHandshake(session.Config{
		Initiator: true, Static: cStatic, PeerStatic: sStatic.Public,
		LocalIndex: 0xA1A1A1A1, Prologue: crypto.Prologue(),
	})
	if err != nil {
		t.Fatal(err)
	}
	m1, _, err := cHS.FramedWrite(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Send(m1); err != nil {
		t.Fatal(err)
	}
	m2, err := conn.Recv()
	if err != nil {
		t.Fatal(err)
	}
	_, cSess, err := cHS.FramedRead(m2)
	if err != nil {
		t.Fatal(err)
	}
	if cSess == nil {
		t.Fatal("клиент не получил сессию")
	}

	plain := []byte("трафик MIRAGE внутри TLS 1.3")
	rec, err := cSess.Seal(session.RecordData, plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Send(rec); err != nil {
		t.Fatal(err)
	}
	back, err := conn.Recv()
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := cSess.Open(back)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("эхо внутри TLS не совпало: %q", got)
	}

	if err := <-srvErr; err != nil {
		t.Fatalf("сервер: %v", err)
	}
}
