package crypto

// MAC1/MAC2 для handshake-кадров (дизайн 03-wire-format §2.2) — дешёвая защита от
// зондов и DoS до выполнения дорогой X25519-операции.
//
// MAC1 = Keyed-BLAKE2s-128( key = BLAKE2s-256(LABEL_MAC1 || s_pub_получателя),
//                           msg = все байты кадра до поля mac1 ).
//
// Ключ зависит от статического публичного ключа ПОЛУЧАТЕЛЯ, который знают обе
// стороны (клиент — pub сервера; сервер — pub клиента, узнанный из msg1). Зонд,
// не знающий нужного pub, не может построить валидный mac1 → сервер отбрасывает
// пакет одним хешем, не тратя X25519 и не выдавая себя (anti-probe / anti-DoS).
//
// MAC2 (cookie-механизм против флуда с подделкой src-IP) пока зарезервирован:
// поле присутствует на проводе (нули), полноценный cookie добавится позже без
// изменения формата.

import (
	"crypto/subtle"

	"golang.org/x/crypto/blake2s"
)

// MacLen — длина одного MAC-поля (mac1, mac2).
const MacLen = 16

// labelMAC1 — доменный разделитель ключа MAC1 (привязка к протоколу MIRAGE).
const labelMAC1 = "MIRAGE mac1 v1"

// mac1Key выводит ключ keyed-BLAKE2s для MAC1 по статическому pub получателя.
func mac1Key(receiverStaticPub []byte) [32]byte {
	in := make([]byte, 0, len(labelMAC1)+len(receiverStaticPub))
	in = append(in, labelMAC1...)
	in = append(in, receiverStaticPub...)
	return blake2s.Sum256(in)
}

// ComputeMAC1 вычисляет mac1 для сообщения msg, адресованного владельцу
// receiverStaticPub.
func ComputeMAC1(receiverStaticPub, msg []byte) [MacLen]byte {
	key := mac1Key(receiverStaticPub)
	h, err := blake2s.New128(key[:])
	if err != nil {
		panic("crypto/mac: blake2s.New128: " + err.Error())
	}
	h.Write(msg)
	var out [MacLen]byte
	copy(out[:], h.Sum(nil))
	return out
}

// VerifyMAC1 проверяет mac1 (константно по времени).
func VerifyMAC1(receiverStaticPub, msg, mac []byte) bool {
	want := ComputeMAC1(receiverStaticPub, msg)
	return subtle.ConstantTimeCompare(want[:], mac) == 1
}
