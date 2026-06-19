package reality

import (
	"bytes"
	"testing"
)

var testPSK = bytes.Repeat([]byte{0x42}, 32)

func TestAuthRoundtrip(t *testing.T) {
	now := int64(1_700_000_000)
	sid, err := makeAuthSessionID(testPSK, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(sid) != sessionIDLen {
		t.Fatalf("длина SessionID %d != 32", len(sid))
	}
	if !verifyAuthSessionID(testPSK, sid, now, newReplayCache()) {
		t.Fatal("валидный токен должен пройти проверку")
	}
}

func TestAuthWrongPSK(t *testing.T) {
	now := int64(1_700_000_000)
	sid, _ := makeAuthSessionID(testPSK, now)
	other := bytes.Repeat([]byte{0x99}, 32)
	if verifyAuthSessionID(other, sid, now, newReplayCache()) {
		t.Fatal("токен под чужим PSK не должен проходить")
	}
}

func TestAuthReplayRejected(t *testing.T) {
	now := int64(1_700_000_000)
	sid, _ := makeAuthSessionID(testPSK, now)
	rc := newReplayCache()
	if !verifyAuthSessionID(testPSK, sid, now, rc) {
		t.Fatal("первый раз — ок")
	}
	if verifyAuthSessionID(testPSK, sid, now, rc) {
		t.Fatal("повтор того же SessionID должен отвергаться")
	}
}

func TestAuthStaleRejected(t *testing.T) {
	old := int64(1_700_000_000)
	sid, _ := makeAuthSessionID(testPSK, old)
	now := old + 1000 // далеко за окном
	if verifyAuthSessionID(testPSK, sid, now, newReplayCache()) {
		t.Fatal("устаревший токен должен отвергаться")
	}
}

func TestAuthTamperRejected(t *testing.T) {
	now := int64(1_700_000_000)
	sid, _ := makeAuthSessionID(testPSK, now)
	sid[20] ^= 0xFF // портим тег
	if verifyAuthSessionID(testPSK, sid, now, newReplayCache()) {
		t.Fatal("испорченный токен должен отвергаться")
	}
}

// Случайный SessionID (как у настоящего браузера) не должен опознаваться как наш.
func TestAuthRandomSessionIDRejected(t *testing.T) {
	random := bytes.Repeat([]byte{0x00}, 32)
	for i := range random {
		random[i] = byte(i * 7)
	}
	if verifyAuthSessionID(testPSK, random, nowUnix(), newReplayCache()) {
		t.Fatal("случайный SessionID браузера не должен проходить как наш")
	}
}
