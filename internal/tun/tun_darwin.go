//go:build darwin

package tun

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// На macOS TUN реализуется через utun (control socket в домене AF_SYSTEM).
// Каждый пакет на чтении/записи предваряется 4-байтовым заголовком семейства
// адресов (AF_INET для IPv4) — его нужно добавлять/снимать.

const (
	sysprotoControl = 2 // SYSPROTO_CONTROL
	utunOptIfname   = 2 // UTUN_OPT_IFNAME
	afHeaderLen     = 4
)

type darwinTUN struct {
	file *os.File
	name string
	mtu  int
	rbuf []byte // буфер чтения (mtu + заголовок)
	wbuf []byte // буфер записи
}

func openTUN(_ string, mtu int) (Device, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("tun: socket(AF_SYSTEM): %w", err)
	}

	info := &unix.CtlInfo{}
	copy(info.Name[:], "com.apple.net.utun_control")
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: CTLIOCGINFO: %w", err)
	}

	// Unit = 0 → ядро выбирает первый свободный utunN.
	sc := &unix.SockaddrCtl{ID: info.Id, Unit: 0}
	if err := unix.Connect(fd, sc); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: connect(utun): %w", err)
	}

	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: получение имени utun: %w", err)
	}

	return &darwinTUN{
		file: os.NewFile(uintptr(fd), name),
		name: name,
		mtu:  mtu,
		rbuf: make([]byte, mtu+afHeaderLen+16),
		wbuf: make([]byte, mtu+afHeaderLen+16),
	}, nil
}

// fromFD оборачивает готовый дескриптор utun (например, от NEPacketTunnelProvider
// на iOS). Семантика та же, что у utun: 4-байтовый AF-заголовок на каждом пакете.
func fromFD(fd, mtu int) (Device, error) {
	return &darwinTUN{
		file: os.NewFile(uintptr(fd), "utun-fd"),
		name: "utun-fd",
		mtu:  mtu,
		rbuf: make([]byte, mtu+afHeaderLen+16),
		wbuf: make([]byte, mtu+afHeaderLen+16),
	}, nil
}

func (t *darwinTUN) Name() string { return t.name }
func (t *darwinTUN) MTU() int     { return t.mtu }

func (t *darwinTUN) ReadPacket(buf []byte) (int, error) {
	n, err := t.file.Read(t.rbuf)
	if err != nil {
		return 0, err
	}
	if n <= afHeaderLen {
		return 0, nil
	}
	return copy(buf, t.rbuf[afHeaderLen:n]), nil
}

func (t *darwinTUN) WritePacket(pkt []byte) (int, error) {
	// 4-байтовый заголовок AF в сетевом порядке. Для IPv4 — AF_INET (2).
	af := uint32(unix.AF_INET)
	if len(pkt) > 0 && pkt[0]>>4 == 6 {
		af = uint32(unix.AF_INET6)
	}
	t.wbuf[0] = byte(af >> 24)
	t.wbuf[1] = byte(af >> 16)
	t.wbuf[2] = byte(af >> 8)
	t.wbuf[3] = byte(af)
	n := copy(t.wbuf[afHeaderLen:], pkt)
	if _, err := t.file.Write(t.wbuf[:afHeaderLen+n]); err != nil {
		return 0, err
	}
	return len(pkt), nil
}

func (t *darwinTUN) Close() error { return t.file.Close() }
