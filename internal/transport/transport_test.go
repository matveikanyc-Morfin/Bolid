package transport

import (
	"bytes"
	"testing"
)

func TestUDPRoundtrip(t *testing.T) {
	srv, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srv.Close()

	cli, err := DialUDP(srv.LocalAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()

	if err := cli.Send([]byte("ping")); err != nil {
		t.Fatalf("send: %v", err)
	}
	got, err := srv.Recv() // сервер выучивает endpoint пира
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if !bytes.Equal(got, []byte("ping")) {
		t.Fatalf("сервер получил %q", got)
	}

	if err := srv.Send([]byte("pong")); err != nil {
		t.Fatalf("server send: %v", err)
	}
	back, err := cli.Recv()
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}
	if !bytes.Equal(back, []byte("pong")) {
		t.Fatalf("клиент получил %q", back)
	}
}

func TestTCPRoundtripAndFraming(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()
		// Эхо двух отдельных записей — проверяем, что обрамление сохраняет границы.
		for i := 0; i < 2; i++ {
			b, err := c.Recv()
			if err != nil {
				errc <- err
				return
			}
			if err := c.Send(b); err != nil {
				errc <- err
				return
			}
		}
		errc <- nil
	}()

	cli, err := DialTCP(ln.LocalAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()

	msgs := [][]byte{[]byte("первая-запись"), bytes.Repeat([]byte("X"), 5000)}
	for _, m := range msgs {
		if err := cli.Send(m); err != nil {
			t.Fatalf("send: %v", err)
		}
		got, err := cli.Recv()
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		if !bytes.Equal(got, m) {
			t.Fatalf("граница записи нарушена: len(got)=%d, ждали %d", len(got), len(m))
		}
	}
	if err := <-errc; err != nil {
		t.Fatalf("сервер: %v", err)
	}
}
