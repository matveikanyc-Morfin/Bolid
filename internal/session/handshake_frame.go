package session

import (
	"encoding/binary"
	"errors"

	"mirage/internal/crypto"
)

// Обрамление handshake-сообщений на проводе (дизайн 03-wire-format §2.2/§2.3):
//
//	[msg_type:1][sender_index:4 LE][ Noise msg, эфемерал → Elligator2 ][mac1:16][mac2:16]
//
//   - msg_type отличает рукопожатие от транспортных записей (демукс на сервере);
//   - sender_index несёт session_id отправителя (маршрутизация ответа);
//   - первые 32 байта Noise-сообщения (эфемерный pub) заменяются на равномерный
//     Elligator2-representative → в первом пакете нет узнаваемой точки кривой;
//   - mac1 = Keyed-BLAKE2s(key=BLAKE2s(LABEL_MAC1||s_pub получателя), кадр до mac1)
//     позволяет получателю отбросить зонд/мусор ОДНИМ хешем, до X25519 (anti-probe);
//   - mac2 зарезервирован под cookie-механизм (сейчас нули).
//
// Значения msg_type выбраны вне диапазона типов записей (0x10+), поэтому первый
// байт пакета однозначно классифицирует его.
const (
	MsgHandshakeInit byte = 0x01 // initiation (клиент → сервер)
	MsgHandshakeResp byte = 0x02 // response   (сервер → клиент)
)

// IndexPrefixLen — длина sender_index.
const IndexPrefixLen = 4

// frameHeaderLen — msg_type + sender_index.
const frameHeaderLen = 1 + IndexPrefixLen

// macTrailerLen — суммарная длина mac1 + mac2 в хвосте кадра.
const macTrailerLen = 2 * crypto.MacLen

var (
	errBadHandshakeFrame = errors.New("session: некорректный handshake-кадр")
	// ErrMAC1 — кадр не прошёл проверку MAC1 (зонд/мусор/чужой). Получатель
	// обязан реагировать молчанием (или релеем на приманку), не выдавая себя.
	ErrMAC1 = errors.New("session: неверный MAC1")
)

// FramedWrite формирует обрамлённое handshake-сообщение: тип + наш localIndex +
// Noise-нагрузка (с Elligator2-эфемералом) + mac1 + mac2. Тип определяется ролью.
func (h *Handshake) FramedWrite(payload []byte) (frame []byte, sess *Session, err error) {
	msg, sess, err := h.WriteMessage(payload)
	if err != nil {
		return nil, nil, err
	}

	// Заменяем «сырой» эфемерный pub (первые 32 байта Noise-сообщения) на его
	// Elligator2-representative — внешне равномерный шум.
	repr, ok := h.suite.EphemeralRepresentative()
	if !ok || len(msg) < crypto.RepresentativeLen {
		return nil, nil, errors.New("session: нет Elligator2-representative эфемерала")
	}
	copy(msg[:crypto.RepresentativeLen], repr[:])

	msgType := MsgHandshakeResp
	if h.initiator {
		msgType = MsgHandshakeInit
	}

	frame = make([]byte, frameHeaderLen+len(msg)+macTrailerLen)
	frame[0] = msgType
	binary.LittleEndian.PutUint32(frame[1:frameHeaderLen], h.localIndex)
	copy(frame[frameHeaderLen:], msg)

	// MAC1 поверх всего кадра до поля mac1, ключ — по статическому pub получателя.
	// hs.PeerStatic() на этот момент известен и инициатору (из конфига), и
	// респонденту (выучен из обработанного init).
	macStart := frameHeaderLen + len(msg)
	receiverPub := h.hs.PeerStatic()
	mac1 := crypto.ComputeMAC1(receiverPub, frame[:macStart])
	copy(frame[macStart:], mac1[:])
	// frame[macStart+MacLen:] (mac2) остаётся нулевым.

	return frame, sess, nil
}

// FramedRead разбирает обрамлённое handshake-сообщение. Порядок: сперва дешёвая
// проверка MAC1 (отбраковка зондов до X25519), затем декодирование Elligator2-
// эфемерала и обработка Noise-части.
func (h *Handshake) FramedRead(frame []byte) (payload []byte, sess *Session, err error) {
	if len(frame) < frameHeaderLen+crypto.RepresentativeLen+macTrailerLen {
		return nil, nil, errBadHandshakeFrame
	}

	// MAC1: ключ — наш собственный статический pub (получатель — мы).
	macStart := len(frame) - macTrailerLen
	if !crypto.VerifyMAC1(h.localStaticPub, frame[:macStart], frame[macStart:macStart+crypto.MacLen]) {
		return nil, nil, ErrMAC1
	}

	h.remoteIndex = binary.LittleEndian.Uint32(frame[1:frameHeaderLen])

	// Восстанавливаем «сырой» эфемерный pub из Elligator2-representative, затем
	// отдаём Noise-сообщение библиотеке (без mac-хвоста).
	noiseMsg := frame[frameHeaderLen:macStart]
	pub := crypto.RepresentativeToPublic(noiseMsg[:crypto.RepresentativeLen])
	copy(noiseMsg[:crypto.RepresentativeLen], pub)

	return h.ReadMessage(noiseMsg)
}
