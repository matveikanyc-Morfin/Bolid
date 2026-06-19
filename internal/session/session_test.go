package session

import (
	"bytes"
	"testing"

	"mirage/internal/crypto"
)

const (
	idClient uint32 = 0xA1A1A1A1
	idServer uint32 = 0xB2B2B2B2
)

var prologue = []byte("MIRAGE/0.1 test")

// establish прогоняет полный Noise_IK обмен и возвращает обе стороны-сессии.
func establish(t *testing.T) (client, server *Session) {
	t.Helper()

	cStatic, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("ключи клиента: %v", err)
	}
	sStatic, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("ключи сервера: %v", err)
	}

	cHS, err := NewHandshake(Config{
		Initiator:  true,
		Static:     cStatic,
		PeerStatic: sStatic.Public,
		LocalIndex: idClient,
		Prologue:   prologue,
	})
	if err != nil {
		t.Fatalf("handshake клиента: %v", err)
	}
	sHS, err := NewHandshake(Config{
		Initiator:  false,
		Static:     sStatic,
		LocalIndex: idServer,
		Prologue:   prologue,
	})
	if err != nil {
		t.Fatalf("handshake сервера: %v", err)
	}
	// Обмен индексами (в реальном протоколе — в заголовках handshake-сообщений).
	cHS.SetRemoteIndex(idServer)
	sHS.SetRemoteIndex(idClient)

	// msg1: client -> server
	msg1, sess, err := cHS.WriteMessage([]byte("hello-from-client"))
	if err != nil {
		t.Fatalf("msg1 write: %v", err)
	}
	if sess != nil {
		t.Fatal("клиент не должен завершить рукопожатие после msg1")
	}
	if _, _, err := sHS.ReadMessage(msg1); err != nil {
		t.Fatalf("msg1 read: %v", err)
	}

	// msg2: server -> client (сервер завершает рукопожатие)
	msg2, server, err := sHS.WriteMessage([]byte("hello-from-server"))
	if err != nil {
		t.Fatalf("msg2 write: %v", err)
	}
	if server == nil {
		t.Fatal("сервер должен получить сессию после msg2")
	}
	_, client, err = cHS.ReadMessage(msg2)
	if err != nil {
		t.Fatalf("msg2 read: %v", err)
	}
	if client == nil {
		t.Fatal("клиент должен получить сессию после чтения msg2")
	}
	return client, server
}

func TestHandshakeAndRoundtrip(t *testing.T) {
	client, server := establish(t)

	// client -> server
	plain := []byte("секретные данные туннеля")
	rec, err := client.Seal(RecordData, plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	typ, got, err := server.Open(rec)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if typ != RecordData {
		t.Fatalf("тип записи: ждали %#x, получили %#x", RecordData, typ)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("payload не совпал: %q != %q", got, plain)
	}

	// server -> client (обратное направление)
	back := []byte("ответ сервера")
	rec2, err := server.Seal(RecordData, back)
	if err != nil {
		t.Fatalf("Seal back: %v", err)
	}
	_, got2, err := client.Open(rec2)
	if err != nil {
		t.Fatalf("Open back: %v", err)
	}
	if !bytes.Equal(got2, back) {
		t.Fatalf("обратный payload не совпал")
	}
}

func TestManyRecordsOrderedAndReordered(t *testing.T) {
	client, server := establish(t)

	var recs [][]byte
	for i := 0; i < 100; i++ {
		r, err := client.Seal(RecordData, []byte{byte(i)})
		if err != nil {
			t.Fatalf("Seal %d: %v", i, err)
		}
		recs = append(recs, r)
	}
	// Доставляем в перемешанном порядке (имитация UDP-реордеринга).
	order := []int{0, 5, 3, 99, 50, 1, 2, 4, 98, 97, 6, 7}
	for _, i := range order {
		typ, pl, err := server.Open(recs[i])
		if err != nil {
			t.Fatalf("Open запись %d: %v", i, err)
		}
		if typ != RecordData || len(pl) != 1 || pl[0] != byte(i) {
			t.Fatalf("запись %d расшифрована неверно", i)
		}
	}
}

func TestReplayRejected(t *testing.T) {
	client, server := establish(t)

	rec, err := client.Seal(RecordData, []byte("once"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, _, err := server.Open(rec); err != nil {
		t.Fatalf("первый Open должен пройти: %v", err)
	}
	// Тот же самый байтовый пакет — повтор.
	if _, _, err := server.Open(rec); err != ErrReplay {
		t.Fatalf("ожидали ErrReplay, получили: %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	client, server := establish(t)

	rec, err := client.Seal(RecordData, []byte("integrity"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Портим последний байт (внутри тега/шифртекста).
	bad := append([]byte(nil), rec...)
	bad[len(bad)-1] ^= 0xFF
	if _, _, err := server.Open(bad); err != ErrAuth {
		t.Fatalf("ожидали ErrAuth на испорченном пакете, получили: %v", err)
	}

	// Портим заголовок (тип записи) — он входит в AAD, тег должен сломаться.
	bad2 := append([]byte(nil), rec...)
	bad2[0] ^= 0x01
	if _, _, err := server.Open(bad2); err == nil {
		t.Fatal("подмена заголовка должна ломать аутентификацию")
	}
}

// TestFramedHandshakeWithMAC прогоняет полный обмен через FramedWrite/FramedRead
// (Elligator2-эфемералы + MAC1) и проверяет, что сессии устанавливаются и
// передают данные в обе стороны.
func TestFramedHandshakeWithMAC(t *testing.T) {
	cStatic, _ := crypto.GenerateKeypair()
	sStatic, _ := crypto.GenerateKeypair()

	cHS, _ := NewHandshake(Config{
		Initiator: true, Static: cStatic, PeerStatic: sStatic.Public,
		LocalIndex: idClient, Prologue: prologue,
	})
	sHS, _ := NewHandshake(Config{
		Initiator: false, Static: sStatic,
		LocalIndex: idServer, Prologue: prologue,
	})

	frame1, sess, err := cHS.FramedWrite([]byte("hi"))
	if err != nil {
		t.Fatalf("FramedWrite init: %v", err)
	}
	if sess != nil {
		t.Fatal("клиент не должен завершить рукопожатие после init")
	}
	if frame1[0] != MsgHandshakeInit {
		t.Fatalf("ожидали MsgHandshakeInit, получили %#x", frame1[0])
	}
	// Хвост mac2 пока нулевой.
	macStart := len(frame1) - macTrailerLen
	for _, b := range frame1[macStart+crypto.MacLen:] {
		if b != 0 {
			t.Fatal("поле mac2 должно быть нулевым (зарезервировано)")
		}
	}

	if _, _, err := sHS.FramedRead(frame1); err != nil {
		t.Fatalf("FramedRead init: %v", err)
	}
	frame2, server, err := sHS.FramedWrite(nil)
	if err != nil || server == nil {
		t.Fatalf("FramedWrite resp: sess=%v err=%v", server, err)
	}
	_, client, err := cHS.FramedRead(frame2)
	if err != nil || client == nil {
		t.Fatalf("FramedRead resp: sess=%v err=%v", client, err)
	}

	// Индексы обменялись через кадры (без ручного SetRemoteIndex).
	rec, err := client.Seal(RecordData, []byte("через ell2+mac"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, got, err := server.Open(rec); err != nil || string(got) != "через ell2+mac" {
		t.Fatalf("Open: got=%q err=%v", got, err)
	}
}

// TestFramedRejectsProbe: зонд, не знающий статический ключ сервера, строит
// неверный MAC1 → сервер отбраковывает кадр (ErrMAC1) ещё до X25519 (anti-probe).
func TestFramedRejectsProbe(t *testing.T) {
	cStatic, _ := crypto.GenerateKeypair()
	sStatic, _ := crypto.GenerateKeypair()
	wrongServer, _ := crypto.GenerateKeypair() // зонд угадывает не тот ключ

	probe, _ := NewHandshake(Config{
		Initiator: true, Static: cStatic, PeerStatic: wrongServer.Public,
		LocalIndex: idClient, Prologue: prologue,
	})
	realServer, _ := NewHandshake(Config{
		Initiator: false, Static: sStatic,
		LocalIndex: idServer, Prologue: prologue,
	})

	frame1, _, err := probe.FramedWrite(nil)
	if err != nil {
		t.Fatalf("FramedWrite: %v", err)
	}
	if _, _, err := realServer.FramedRead(frame1); err != ErrMAC1 {
		t.Fatalf("ожидали ErrMAC1 для зонда, получили: %v", err)
	}
}

// TestFramedTamperedMAC1: подмена байта в поле mac1 → ErrMAC1.
func TestFramedTamperedMAC1(t *testing.T) {
	cStatic, _ := crypto.GenerateKeypair()
	sStatic, _ := crypto.GenerateKeypair()

	cHS, _ := NewHandshake(Config{
		Initiator: true, Static: cStatic, PeerStatic: sStatic.Public,
		LocalIndex: idClient, Prologue: prologue,
	})
	sHS, _ := NewHandshake(Config{
		Initiator: false, Static: sStatic,
		LocalIndex: idServer, Prologue: prologue,
	})

	frame1, _, _ := cHS.FramedWrite(nil)
	macStart := len(frame1) - macTrailerLen
	frame1[macStart] ^= 0x01 // портим mac1
	if _, _, err := sHS.FramedRead(frame1); err != ErrMAC1 {
		t.Fatalf("ожидали ErrMAC1 при подмене mac1, получили: %v", err)
	}
}

func TestWrongPrologueFailsHandshake(t *testing.T) {
	cStatic, _ := crypto.GenerateKeypair()
	sStatic, _ := crypto.GenerateKeypair()

	cHS, _ := NewHandshake(Config{
		Initiator: true, Static: cStatic, PeerStatic: sStatic.Public,
		LocalIndex: idClient, Prologue: []byte("version-A"),
	})
	sHS, _ := NewHandshake(Config{
		Initiator: false, Static: sStatic,
		LocalIndex: idServer, Prologue: []byte("version-B"), // расхождение!
	})

	msg1, _, err := cHS.WriteMessage(nil)
	if err != nil {
		t.Fatalf("msg1: %v", err)
	}
	// Разный prologue → транскрипт-хеши расходятся → аутентификация msg1 падает.
	if _, _, err := sHS.ReadMessage(msg1); err == nil {
		t.Fatal("рукопожатие с разным prologue должно проваливаться (downgrade-protection)")
	}
}
