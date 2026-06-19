// Package tun предоставляет кроссплатформенный доступ к TUN-устройству (L4
// L3-профиля): чтение и запись сырых IP-пакетов. Это «нижняя» точка туннеля —
// пакеты из ОС попадают сюда, шифруются сессией и уходят в сеть, и наоборот.
//
// Реализации:
//   - Linux:  /dev/net/tun (IFF_TUN|IFF_NO_PI) — пакеты без префикса.
//   - macOS:  utun (control socket) — пакеты с 4-байтовым AF-заголовком.
package tun

// Device — открытое TUN-устройство. Одно устройство рассчитано на одного
// читателя и одного писателя (обычно две горутины tx/rx).
type Device interface {
	// Name возвращает фактическое имя интерфейса (например, "mirage0", "utun4").
	Name() string
	// MTU возвращает настроенный MTU.
	MTU() int
	// ReadPacket читает один IP-пакет в buf и возвращает его длину.
	ReadPacket(buf []byte) (int, error)
	// WritePacket пишет один IP-пакет в устройство.
	WritePacket(pkt []byte) (int, error)
	// Close закрывает устройство.
	Close() error
}

// Open создаёт/открывает TUN-устройство. На macOS имя игнорируется (ядро
// выдаёт utunN автоматически); фактическое имя доступно через Name().
func Open(name string, mtu int) (Device, error) {
	return openTUN(name, mtu)
}

// FromFD оборачивает уже открытый файловый дескриптор TUN/utun. Используется,
// когда устройство создаёт ОС/фреймворк (например, NEPacketTunnelProvider на iOS
// отдаёт fd utun) — библиотека не открывает драйвер сама.
func FromFD(fd, mtu int) (Device, error) {
	return fromFD(fd, mtu)
}
