package reality

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Скрытый аутентификатор клиента прячется в поле SessionID ClientHello (32 байта).
// Снаружи это выглядит как обычный случайный SessionID (TLS 1.3 compat-mode), но
// для сервера с общим reality-PSK он расшифровывается и подтверждает «свой клиент».
//
//	SessionID(32) = nonce(8) || AEAD_ChaCha20Poly1305(key, nonce||0000, ts(8))
//	              = nonce(8) || ciphertext(8) || tag(16)
//
// Без PSK подделать токен нельзя → зонд не пройдёт аутентификацию и будет
// прозрачно сброшен на реальный сайт-приманку.

const (
	sessionIDLen = 32
	noncePrefix  = 8
	tsLen        = 8

	// authWindow — допустимый разброс времени (anti-replay handshake).
	authWindow = 120 // секунд
)

func deriveAuthKey(psk []byte) []byte {
	r := hkdf.New(sha256.New, psk, []byte("mirage-reality-v1"), []byte("clienthello-auth"))
	key := make([]byte, chacha20poly1305.KeySize)
	_, _ = io.ReadFull(r, key)
	return key
}

func aeadNonce(prefix []byte) []byte {
	n := make([]byte, chacha20poly1305.NonceSize) // 12
	copy(n, prefix)                               // 8 байт префикса + 4 нуля
	return n
}

// makeAuthSessionID формирует 32-байтовый SessionID с токеном на текущий момент.
func makeAuthSessionID(psk []byte, nowUnix int64) ([]byte, error) {
	key := deriveAuthKey(psk)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	sid := make([]byte, sessionIDLen)
	if _, err := rand.Read(sid[:noncePrefix]); err != nil {
		return nil, err
	}
	var ts [tsLen]byte
	binary.BigEndian.PutUint64(ts[:], uint64(nowUnix))
	ct := aead.Seal(nil, aeadNonce(sid[:noncePrefix]), ts[:], nil) // 8 + 16 = 24
	copy(sid[noncePrefix:], ct)
	return sid, nil
}

// verifyAuthSessionID проверяет токен: подлинность (AEAD), свежесть (окно) и
// отсутствие повтора. Возвращает true только для валидного свежего нового токена.
func verifyAuthSessionID(psk, sid []byte, nowUnix int64, replay *replayCache) bool {
	if len(sid) != sessionIDLen {
		return false
	}
	key := deriveAuthKey(psk)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return false
	}
	pt, err := aead.Open(nil, aeadNonce(sid[:noncePrefix]), sid[noncePrefix:], nil)
	if err != nil || len(pt) != tsLen {
		return false
	}
	ts := int64(binary.BigEndian.Uint64(pt))
	if ts < nowUnix-authWindow || ts > nowUnix+authWindow {
		return false // вне окна — устаревший/будущий
	}
	return replay.checkAndAdd(sid, nowUnix)
}

// replayCache хранит уже виденные SessionID в пределах окна (anti-replay).
type replayCache struct {
	mu   sync.Mutex
	seen map[string]int64 // key → unix-время добавления
}

func newReplayCache() *replayCache {
	return &replayCache{seen: make(map[string]int64)}
}

// checkAndAdd возвращает true, если sid ранее не встречался (и регистрирует его).
func (c *replayCache) checkAndAdd(sid []byte, nowUnix int64) bool {
	key := string(sid)
	c.mu.Lock()
	defer c.mu.Unlock()
	// периодическая чистка устаревших записей
	for k, t := range c.seen {
		if t < nowUnix-2*authWindow {
			delete(c.seen, k)
		}
	}
	if _, ok := c.seen[key]; ok {
		return false // повтор
	}
	c.seen[key] = nowUnix
	return true
}

// nowUnix — обёртка для времени (упрощает тесты).
func nowUnix() int64 { return time.Now().Unix() }
