//go:build !linux && !darwin

package tun

import (
	"errors"
	"runtime"
)

// На неподдерживаемых платформах TUN недоступен (Windows — отдельная задача
// Фазы 4 через Wintun).
func openTUN(_ string, _ int) (Device, error) {
	return nil, errors.New("tun: платформа " + runtime.GOOS + " пока не поддерживается")
}

func fromFD(_, _ int) (Device, error) {
	return nil, errors.New("tun: платформа " + runtime.GOOS + " пока не поддерживается")
}
