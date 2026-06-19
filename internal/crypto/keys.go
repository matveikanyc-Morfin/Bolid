// Package crypto собирает криптографический набор MIRAGE поверх проверенных
// библиотек. Своих примитивов здесь нет — только конфигурация Noise и
// удобные обёртки (генерация/кодирование ключей).
//
// Набор (см. дизайн 01-spec §6):
//
//	Noise_IK_25519_ChaChaPoly_BLAKE2s
//	DH:   X25519
//	AEAD: ChaCha20-Poly1305
//	Hash: BLAKE2s
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

// Suite — криптонабор протокола. Един для всех сессий.
var Suite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// KeyLen — длина X25519-ключа в байтах.
const KeyLen = 32

// Keypair — статическая пара X25519 (алиас типа Noise, чтобы вызывающий код
// не зависел напрямую от библиотеки).
type Keypair = noise.DHKey

// GenerateKeypair создаёт статическую пару X25519.
func GenerateKeypair() (Keypair, error) {
	return Suite.GenerateKeypair(rand.Reader)
}

// KeypairFromPrivate восстанавливает пару по приватному ключу, вычисляя
// соответствующий публичный X25519-ключ.
func KeypairFromPrivate(priv []byte) (Keypair, error) {
	if len(priv) != KeyLen {
		return Keypair{}, errors.New("неверная длина приватного ключа (ожидалось 32 байта)")
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return Keypair{}, fmt.Errorf("вывод публичного ключа: %w", err)
	}
	return Keypair{Private: append([]byte(nil), priv...), Public: pub}, nil
}

// EncodeKey кодирует ключ в base64url (формат конфигурации и share-URI).
func EncodeKey(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

// DecodeKey разбирает base64url-ключ и проверяет длину.
func DecodeKey(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("декодирование ключа: %w", err)
	}
	if len(b) != KeyLen {
		return nil, errors.New("неверная длина ключа (ожидалось 32 байта)")
	}
	return b, nil
}
