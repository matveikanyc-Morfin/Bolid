package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// genEll2 генерирует эфемерал с валидным Elligator2-representative (rejection
// sampling), как это делает ell2DH внутри Noise.
func genEll2(t *testing.T) (priv, pub, repr [32]byte) {
	t.Helper()
	for {
		if _, err := rand.Read(priv[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		var tweak [1]byte
		if _, err := rand.Read(tweak[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		if scalarBaseMult(&pub, &repr, &priv, tweak[0]) {
			return priv, pub, repr
		}
	}
}

// TestEll2RoundTrip: декодирование representative должно давать ровно тот pub,
// который вернул encode (самосогласованность прямого и обратного отображения).
func TestEll2RoundTrip(t *testing.T) {
	for i := 0; i < 64; i++ {
		_, pub, repr := genEll2(t)
		got := RepresentativeToPublic(repr[:])
		if !bytes.Equal(got, pub[:]) {
			t.Fatalf("итерация %d: decode(repr) != pub\n pub=%x\n got=%x", i, pub, got)
		}
	}
}

// TestEll2HighBitsRandomised: две старшие «паддинг»-бита representative должны
// варьироваться (иначе появляется статический признак). Проверяем, что по выборке
// встречаются разные значения битов 6–7 старшего байта.
func TestEll2HighBitsRandomised(t *testing.T) {
	seen := map[byte]bool{}
	for i := 0; i < 128; i++ {
		_, _, repr := genEll2(t)
		seen[repr[31]&0xc0] = true
	}
	if len(seen) < 2 {
		t.Fatalf("старшие биты representative не рандомизируются: %v", seen)
	}
}

// TestEll2DHAgreement: несмотря на «грязный» (не очищающий кофактор) pub, ECDH
// совпадает с обычным X25519 — клампинг скаляра убирает компоненту малого порядка.
func TestEll2DHAgreement(t *testing.T) {
	for i := 0; i < 16; i++ {
		ePriv, ePub, repr := genEll2(t)

		// Статический партнёр (обычный X25519).
		var sPriv [32]byte
		if _, err := rand.Read(sPriv[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		sPub, err := curve25519.X25519(sPriv[:], curve25519.Basepoint)
		if err != nil {
			t.Fatalf("X25519: %v", err)
		}

		// Наша сторона: DH(ePriv, sPub).
		shared1, err := curve25519.X25519(ePriv[:], sPub)
		if err != nil {
			t.Fatalf("X25519: %v", err)
		}
		// Партнёр восстанавливает наш pub из representative и считает DH(sPriv, ePub').
		recovered := RepresentativeToPublic(repr[:])
		if !bytes.Equal(recovered, ePub[:]) {
			t.Fatalf("decode(repr) != ePub")
		}
		shared2, err := curve25519.X25519(sPriv[:], recovered)
		if err != nil {
			t.Fatalf("X25519: %v", err)
		}
		if !bytes.Equal(shared1, shared2) {
			t.Fatalf("итерация %d: DH-секреты расходятся\n s1=%x\n s2=%x", i, shared1, shared2)
		}
	}
}

// TestHandshakeSuiteCapture: набор Noise с Elligator2 действительно перехватывает
// representative сгенерированного эфемерала, и тот декодируется в его pub.
func TestHandshakeSuiteCapture(t *testing.T) {
	suite := NewHandshakeSuite()
	if _, ok := suite.EphemeralRepresentative(); ok {
		t.Fatal("representative не должен быть готов до генерации ключа")
	}
	kp, err := suite.Suite.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	repr, ok := suite.EphemeralRepresentative()
	if !ok {
		t.Fatal("representative не перехвачен")
	}
	if got := RepresentativeToPublic(repr[:]); !bytes.Equal(got, kp.Public) {
		t.Fatalf("decode(repr) != сгенерированный pub\n pub=%x\n got=%x", kp.Public, got)
	}
}
