package crypto

import (
	"crypto/rand"
	"testing"
)

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// TestMAC1Verify: валидный mac1 проходит, а подмена pub-ключа, сообщения или
// самого тега — отвергается.
func TestMAC1Verify(t *testing.T) {
	recvPub := randBytes(t, KeyLen)
	msg := randBytes(t, 96)
	mac := ComputeMAC1(recvPub, msg)

	if !VerifyMAC1(recvPub, msg, mac[:]) {
		t.Fatal("валидный MAC1 не прошёл проверку")
	}

	// Чужой pub получателя (зонд не знает ключ сервера).
	otherPub := randBytes(t, KeyLen)
	if VerifyMAC1(otherPub, msg, mac[:]) {
		t.Fatal("MAC1 принят с чужим pub-ключом")
	}

	// Подмена одного байта сообщения.
	tampered := append([]byte(nil), msg...)
	tampered[10] ^= 0x01
	if VerifyMAC1(recvPub, tampered, mac[:]) {
		t.Fatal("MAC1 принят для изменённого сообщения")
	}

	// Подмена тега.
	badMac := append([]byte(nil), mac[:]...)
	badMac[0] ^= 0x80
	if VerifyMAC1(recvPub, msg, badMac) {
		t.Fatal("повреждённый MAC1 принят")
	}
}

// TestMAC1Deterministic: один и тот же вход даёт один и тот же тег.
func TestMAC1Deterministic(t *testing.T) {
	pub := randBytes(t, KeyLen)
	msg := randBytes(t, 64)
	a := ComputeMAC1(pub, msg)
	b := ComputeMAC1(pub, msg)
	if a != b {
		t.Fatal("MAC1 недетерминирован")
	}
}
