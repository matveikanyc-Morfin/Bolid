package session

import (
	"encoding/binary"
	"errors"
)

// Формат транспортной записи (data plane), см. дизайн 03-wire-format §3:
//
//	[type:1][session_id:4 LE][counter:8 LE][ AEAD ciphertext+tag ]
//
// Первые 13 байт (заголовок) используются как associated data (AAD) при AEAD,
// поэтому подмена типа/индекса/счётчика делает тег невалидным.

// HeaderLen — длина заголовка записи (type + session_id + counter).
const HeaderLen = 1 + 4 + 8

// Типы записей (data plane).
const (
	RecordData      byte = 0x10 // полезная нагрузка (mux-кадры)
	RecordKeepalive byte = 0x11 // пустой payload, поддержание сессии/NAT
	RecordRekey     byte = 0x12 // инициирование ротации ключей
	RecordRoamProbe byte = 0x13 // подтверждение нового endpoint
	RecordClose     byte = 0x14 // корректное закрытие
)

var errShortRecord = errors.New("session: запись короче заголовка")

// header описывает разобранный заголовок записи.
type header struct {
	typ       byte
	sessionID uint32
	counter   uint64
}

// encodeHeader пишет заголовок в начало dst (должен быть длиной >= HeaderLen)
// и возвращает срез заголовка (для использования как AAD).
func encodeHeader(dst []byte, h header) []byte {
	dst[0] = h.typ
	binary.LittleEndian.PutUint32(dst[1:5], h.sessionID)
	binary.LittleEndian.PutUint64(dst[5:13], h.counter)
	return dst[:HeaderLen]
}

// RecordSessionID извлекает session_id из заголовка записи без расшифровки —
// нужно серверу, чтобы выбрать сессию из нескольких (multi-peer) до Open.
func RecordSessionID(record []byte) (uint32, bool) {
	if len(record) < HeaderLen {
		return 0, false
	}
	return binary.LittleEndian.Uint32(record[1:5]), true
}

// parseHeader разбирает заголовок из начала record.
func parseHeader(record []byte) (header, error) {
	if len(record) < HeaderLen {
		return header{}, errShortRecord
	}
	return header{
		typ:       record[0],
		sessionID: binary.LittleEndian.Uint32(record[1:5]),
		counter:   binary.LittleEndian.Uint64(record[5:13]),
	}, nil
}
