// Package session реализует слой L2 протокола MIRAGE: рукопожатие Noise_IK,
// шифрование транспортных записей AEAD, счётчики nonce и защиту от повторов.
//
// Рукопожатие и AEAD выполняет библиотека flynn/noise; этот пакет добавляет
// формат записи, управление счётчиками и интеграцию с anti-replay окном.
package session

import (
	"errors"
	"fmt"

	"mirage/internal/crypto"
	"mirage/internal/replay"

	"github.com/flynn/noise"
)

var (
	// ErrReplay — счётчик уже видели (повтор/дубликат) либо он вне окна.
	ErrReplay = errors.New("session: повтор пакета (replay)")
	// ErrAuth — запись не прошла AEAD-аутентификацию.
	ErrAuth = errors.New("session: ошибка аутентификации записи")
	// ErrNotEstablished — операция до завершения рукопожатия.
	ErrNotEstablished = errors.New("session: сессия не установлена")
)

// Session — установленная защищённая сессия (после рукопожатия).
// Не потокобезопасна: отправка и приём должны сериализоваться вызывающим кодом
// (обычно отдельные горутины tx/rx с собственными блокировками).
type Session struct {
	send *noise.CipherState // шифрование исходящих
	recv *noise.CipherState // расшифровка входящих

	sendCounter uint64         // монотонный nonce-счётчик отправителя
	recvFilter  *replay.Filter // окно anti-replay для входящих

	// Индексы маршрутизации (см. 02-architecture §2.2).
	localIndex  uint32 // какой session_id ждём во входящих записях
	remoteIndex uint32 // какой session_id ставим в исходящие
}

// LocalIndex возвращает индекс, который сессия ожидает во входящих записях.
func (s *Session) LocalIndex() uint32 { return s.localIndex }

// Seal шифрует payload в транспортную запись типа typ и возвращает её байты.
func (s *Session) Seal(typ byte, payload []byte) ([]byte, error) {
	if s.send == nil {
		return nil, ErrNotEstablished
	}
	counter := s.sendCounter

	out := make([]byte, HeaderLen, HeaderLen+len(payload)+16)
	ad := encodeHeader(out, header{typ: typ, sessionID: s.remoteIndex, counter: counter})

	// flynn/noise управляет nonce внутри CipherState; синхронизируем его с нашим
	// счётчиком, чтобы значение в заголовке совпадало с nonce AEAD.
	s.send.SetNonce(counter)
	out, err := s.send.Encrypt(out, ad, payload)
	if err != nil {
		return nil, fmt.Errorf("session: шифрование записи: %w", err)
	}

	s.sendCounter++
	return out, nil
}

// Open расшифровывает входящую запись. Возвращает её тип и расшифрованный
// payload. Порядок проверок: сперва AEAD-аутентификация (отсекает подделки),
// затем anti-replay (отсекает валидные повторы).
func (s *Session) Open(record []byte) (typ byte, payload []byte, err error) {
	if s.recv == nil {
		return 0, nil, ErrNotEstablished
	}
	h, err := parseHeader(record)
	if err != nil {
		return 0, nil, err
	}
	if h.sessionID != s.localIndex {
		return 0, nil, fmt.Errorf("session: чужой session_id %d (ждём %d)", h.sessionID, s.localIndex)
	}

	ad := record[:HeaderLen]
	ciphertext := record[HeaderLen:]

	s.recv.SetNonce(h.counter)
	pt, err := s.recv.Decrypt(nil, ad, ciphertext)
	if err != nil {
		return 0, nil, ErrAuth
	}

	// Аутентифицировано — теперь проверяем свежесть счётчика.
	if !s.recvFilter.ValidateAndAdd(h.counter) {
		return 0, nil, ErrReplay
	}
	return h.typ, pt, nil
}

// newSession строит Session из пары CipherState, выданной Noise.Split().
// В flynn/noise возвращаемая пара (cs0, cs1) направлена так: cs0 — для
// сообщений инициатора, cs1 — для сообщений респондента.
func newSession(initiator bool, cs0, cs1 *noise.CipherState, localIndex, remoteIndex uint32) *Session {
	s := &Session{
		recvFilter:  replay.New(replay.DefaultWindowBits),
		localIndex:  localIndex,
		remoteIndex: remoteIndex,
	}
	if initiator {
		s.send, s.recv = cs0, cs1
	} else {
		s.send, s.recv = cs1, cs0
	}
	return s
}

// --- Рукопожатие (Noise_IK) ---

// Handshake управляет одной стороной рукопожатия Noise_IK.
type Handshake struct {
	hs          *noise.HandshakeState
	suite       *crypto.HandshakeSuite // Elligator2-эфемералы + перехват representative
	initiator   bool
	localIndex  uint32
	remoteIndex uint32

	localStaticPub []byte // наш статический pub — ключ MAC1, когда получатель мы (FramedRead)
}

// Config — параметры стороны рукопожатия.
type Config struct {
	Initiator  bool        // true для клиента (инициатора)
	Static     noise.DHKey // своя статическая пара X25519
	PeerStatic []byte      // статический pub сервера (обязателен для инициатора в IK)
	LocalIndex uint32      // индекс, который мы присваиваем этой сессии
	Prologue   []byte      // привязка параметров (версия/suite) — защита от downgrade
}

// NewHandshake создаёт сторону рукопожатия по паттерну Noise_IK.
func NewHandshake(cfg Config) (*Handshake, error) {
	suite := crypto.NewHandshakeSuite() // эфемералы маскируются Elligator2
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite.Suite,
		Pattern:       noise.HandshakeIK,
		Initiator:     cfg.Initiator,
		StaticKeypair: cfg.Static,
		PeerStatic:    cfg.PeerStatic,
		Prologue:      cfg.Prologue,
	})
	if err != nil {
		return nil, fmt.Errorf("session: создание Noise-состояния: %w", err)
	}
	return &Handshake{
		hs:             hs,
		suite:          suite,
		initiator:      cfg.Initiator,
		localIndex:     cfg.LocalIndex,
		localStaticPub: cfg.Static.Public,
	}, nil
}

// PeerStatic возвращает статический публичный ключ другой стороны, узнанный в
// ходе рукопожатия (после обработки соответствующего сообщения). На сервере
// используется для аутентификации клиента по его ключу (multi-peer).
func (h *Handshake) PeerStatic() []byte { return h.hs.PeerStatic() }

// SetRemoteIndex задаёт индекс, полученный от другой стороны (для маршрутизации
// исходящих записей). В реальном протоколе индекс несёт заголовок handshake-
// сообщения; на этом этапе он передаётся явно.
func (h *Handshake) SetRemoteIndex(idx uint32) { h.remoteIndex = idx }

// WriteMessage формирует очередное handshake-сообщение с необязательным payload.
// Если рукопожатие на этом шаге завершается, возвращает готовую *Session.
func (h *Handshake) WriteMessage(payload []byte) (msg []byte, sess *Session, err error) {
	out, cs0, cs1, err := h.hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("session: WriteMessage: %w", err)
	}
	if cs0 != nil {
		sess = newSession(h.initiator, cs0, cs1, h.localIndex, h.remoteIndex)
	}
	return out, sess, nil
}

// ReadMessage обрабатывает входящее handshake-сообщение и возвращает вложенный
// payload. Если рукопожатие завершилось, возвращает готовую *Session.
func (h *Handshake) ReadMessage(msg []byte) (payload []byte, sess *Session, err error) {
	pl, cs0, cs1, err := h.hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("session: ReadMessage: %w", err)
	}
	if cs0 != nil {
		sess = newSession(h.initiator, cs0, cs1, h.localIndex, h.remoteIndex)
	}
	return pl, sess, nil
}
