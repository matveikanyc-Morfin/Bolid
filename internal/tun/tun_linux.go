//go:build linux

package tun

import (
	"bytes"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ifreq для TUNSETIFF: имя интерфейса + флаги. Полный размер struct ifreq на
// Linux — 40 байт (IFNAMSIZ=16 имя, 2 флаги, остальное — паддинг объединения).
type ifreqFlags struct {
	name  [unix.IFNAMSIZ]byte
	flags uint16
	_     [40 - unix.IFNAMSIZ - 2]byte
}

type linuxTUN struct {
	file *os.File
	name string
	mtu  int
}

func openTUN(name string, mtu int) (Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: открытие /dev/net/tun: %w", err)
	}

	var req ifreqFlags
	copy(req.name[:unix.IFNAMSIZ-1], name)
	// IFF_TUN — L3 (IP) устройство; IFF_NO_PI — без 4-байтового префикса пакета.
	req.flags = unix.IFF_TUN | unix.IFF_NO_PI

	if _, _, errno := unix.Syscall(
		unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req)),
	); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: TUNSETIFF: %w", errno)
	}

	actual := string(bytes.TrimRight(req.name[:], "\x00"))
	return &linuxTUN{
		file: os.NewFile(uintptr(fd), "/dev/net/tun"),
		name: actual,
		mtu:  mtu,
	}, nil
}

// fromFD оборачивает готовый дескриптор TUN (IFF_NO_PI — сырые IP-пакеты).
func fromFD(fd, mtu int) (Device, error) {
	return &linuxTUN{file: os.NewFile(uintptr(fd), "tun-fd"), name: "tun", mtu: mtu}, nil
}

func (t *linuxTUN) Name() string                    { return t.name }
func (t *linuxTUN) MTU() int                        { return t.mtu }
func (t *linuxTUN) ReadPacket(buf []byte) (int, error)  { return t.file.Read(buf) }
func (t *linuxTUN) WritePacket(pkt []byte) (int, error) { return t.file.Write(pkt) }
func (t *linuxTUN) Close() error                    { return t.file.Close() }
