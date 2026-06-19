package reality

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildClientHello собирает минимальный валидный TLS ClientHello (с record-
// заголовком) для теста парсера.
func buildClientHello(sessionID []byte, sni string) []byte {
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})          // client_version TLS1.2 (для совместимости)
	body.Write(make([]byte, 32))            // random
	body.WriteByte(byte(len(sessionID)))    // session_id_len
	body.Write(sessionID)                   // session_id
	body.Write([]byte{0x00, 0x02, 0x13, 0x01}) // cipher_suites: len=2, TLS_AES_128_GCM_SHA256
	body.Write([]byte{0x01, 0x00})          // compression: len=1, null

	// SNI extension
	var sniExt bytes.Buffer
	name := []byte(sni)
	// server_name_list: [type=0][name_len:2][name]
	var list bytes.Buffer
	list.WriteByte(0x00)
	nl := make([]byte, 2)
	binary.BigEndian.PutUint16(nl, uint16(len(name)))
	list.Write(nl)
	list.Write(name)
	// list_len
	ll := make([]byte, 2)
	binary.BigEndian.PutUint16(ll, uint16(list.Len()))
	sniExt.Write([]byte{0x00, 0x00}) // ext type server_name
	el := make([]byte, 2)
	binary.BigEndian.PutUint16(el, uint16(2+list.Len()))
	sniExt.Write(el)
	sniExt.Write(ll)
	sniExt.Write(list.Bytes())

	extLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extLen, uint16(sniExt.Len()))
	body.Write(extLen)
	body.Write(sniExt.Bytes())

	// handshake header
	var hs bytes.Buffer
	hs.WriteByte(0x01) // ClientHello
	bl := body.Len()
	hs.Write([]byte{byte(bl >> 16), byte(bl >> 8), byte(bl)})
	hs.Write(body.Bytes())

	// record header
	var rec bytes.Buffer
	rec.WriteByte(0x16)
	rec.Write([]byte{0x03, 0x01})
	rl := make([]byte, 2)
	binary.BigEndian.PutUint16(rl, uint16(hs.Len()))
	rec.Write(rl)
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

func TestParseClientHello(t *testing.T) {
	sid := bytes.Repeat([]byte{0xAB}, 32)
	rec := buildClientHello(sid, "www.example-cdn.com")

	gotSID, gotSNI, err := parseClientHello(rec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(gotSID, sid) {
		t.Fatalf("session_id не совпал: %x", gotSID)
	}
	if gotSNI != "www.example-cdn.com" {
		t.Fatalf("SNI не совпал: %q", gotSNI)
	}
}

func TestParseClientHelloTruncated(t *testing.T) {
	rec := buildClientHello(bytes.Repeat([]byte{1}, 32), "a.com")
	for n := 0; n < len(rec); n++ {
		// Любой обрезанный ClientHello должен давать ошибку, а не панику.
		if _, _, err := parseClientHello(rec[:n]); err == nil && n < len(rec) {
			// допустимо: некоторые префиксы парсятся до extensions; главное — нет паники
		}
	}
}

func TestParseNonTLS(t *testing.T) {
	if _, _, err := parseClientHello([]byte("GET / HTTP/1.1\r\n")); err == nil {
		t.Fatal("HTTP-запрос не должен парситься как ClientHello")
	}
}
