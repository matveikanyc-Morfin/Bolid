// Package transport реализует слой L1 протокола MIRAGE: доставку записей поверх
// UDP и TCP. Слой message-ориентирован — одна операция Send/Recv соответствует
// одной транспортной записи (см. дизайн 03-wire-format §3.3).
//
//   - UDP: одна датаграмма = одна запись (граница задаётся транспортом).
//   - TCP: поток с обрамлением длиной [len:2 BE][record].
//
// Обфускация/мимикрия (Elligator, TLS-Reality и т.п.) — отдельные обёртки над
// этим слоем, появятся в подпакете obfs (Фаза 3).
package transport

// MaxRecordSize — верхняя граница размера одной записи на проводе.
const MaxRecordSize = 65535

// Conn — двунаправленный канал доставки записей.
// Реализации: *UDPClient, *UDPServer, *StreamConn (TCP).
type Conn interface {
	// Send отправляет одну запись целиком.
	Send(record []byte) error
	// Recv блокирующе принимает одну запись.
	Recv() ([]byte, error)
	// Close закрывает соединение.
	Close() error
}
