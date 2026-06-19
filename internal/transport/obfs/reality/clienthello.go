// Package reality реализует профиль обфускации tls-reality с защитой от
// активного зондирования (шаг 3b). Сервер подсматривает TLS ClientHello и решает:
//
//   - есть валидный скрытый токен в SessionID  → это клиент MIRAGE (hijack + туннель);
//   - нет токена (браузер/зонд ТСПУ)           → прозрачный релей на реальный dest.
//
// Так зонд всегда видит легитимный сайт, а адрес сервера не палится.
package reality

import (
	"encoding/binary"
	"errors"
)

var errParseCH = errors.New("reality: не удалось разобрать ClientHello")

// parseClientHello извлекает session_id и SNI из полной TLS-записи (с 5-байтовым
// заголовком record). Парсер минимальный и строго проверяет границы.
func parseClientHello(rec []byte) (sessionID []byte, sni string, err error) {
	// TLS record header: [type=0x16][version:2][length:2]
	if len(rec) < 5 || rec[0] != 0x16 {
		return nil, "", errParseCH
	}
	recLen := int(binary.BigEndian.Uint16(rec[3:5]))
	if recLen == 0 || 5+recLen > len(rec) {
		return nil, "", errParseCH
	}
	hs := rec[5 : 5+recLen]

	// Handshake header: [type=0x01 ClientHello][length:3]
	if len(hs) < 4 || hs[0] != 0x01 {
		return nil, "", errParseCH
	}
	bodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+bodyLen > len(hs) {
		return nil, "", errParseCH
	}
	b := hs[4 : 4+bodyLen]

	// body: client_version(2) + random(32)
	p := 2 + 32
	if p > len(b) {
		return nil, "", errParseCH
	}
	// session_id
	if p+1 > len(b) {
		return nil, "", errParseCH
	}
	sidLen := int(b[p])
	p++
	if p+sidLen > len(b) {
		return nil, "", errParseCH
	}
	sessionID = b[p : p+sidLen]
	p += sidLen

	// cipher_suites
	if p+2 > len(b) {
		return nil, "", errParseCH
	}
	csLen := int(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2 + csLen
	if p > len(b) {
		return nil, "", errParseCH
	}
	// compression_methods
	if p+1 > len(b) {
		return nil, "", errParseCH
	}
	cmLen := int(b[p])
	p += 1 + cmLen
	if p > len(b) {
		return nil, "", errParseCH
	}
	// extensions (могут отсутствовать)
	if p+2 > len(b) {
		return sessionID, "", nil
	}
	extLen := int(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	if p+extLen > len(b) {
		return nil, "", errParseCH
	}
	sni = parseSNI(b[p : p+extLen])
	return sessionID, sni, nil
}

// parseSNI достаёт первый host_name из расширения server_name (тип 0x0000).
func parseSNI(ext []byte) string {
	for len(ext) >= 4 {
		etype := binary.BigEndian.Uint16(ext[0:2])
		elen := int(binary.BigEndian.Uint16(ext[2:4]))
		if 4+elen > len(ext) {
			return ""
		}
		data := ext[4 : 4+elen]
		ext = ext[4+elen:]
		if etype != 0x0000 { // не server_name
			continue
		}
		// server_name_list: [list_len:2] { [type:1][name_len:2][name] }
		if len(data) < 2 {
			return ""
		}
		listLen := int(binary.BigEndian.Uint16(data[0:2]))
		d := data[2:]
		if listLen > len(d) {
			return ""
		}
		for len(d) >= 3 {
			nameType := d[0]
			nameLen := int(binary.BigEndian.Uint16(d[1:3]))
			if 3+nameLen > len(d) {
				return ""
			}
			if nameType == 0x00 { // host_name
				return string(d[3 : 3+nameLen])
			}
			d = d[3+nameLen:]
		}
		return ""
	}
	return ""
}
