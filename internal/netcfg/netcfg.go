// Package netcfg настраивает сетевое окружение туннеля: адрес/MTU на TUN-
// интерфейсе и (на сервере) NAT для выхода в интернет. Реализовано через вызов
// системных утилит (ip/iptables/ifconfig) — это надёжнее и прозрачнее, чем
// прямой netlink, на старте проекта.
package netcfg

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ConfigureInterface назначает адрес, MTU и поднимает интерфейс.
//
//	localCIDR — адрес с маской, напр. "10.7.0.1/24".
//	peerIP    — адрес другого конца (нужен только для point-to-point utun на macOS;
//	            на Linux игнорируется).
func ConfigureInterface(name, localCIDR, peerIP string, mtu int) error {
	switch runtime.GOOS {
	case "linux":
		if err := run("ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "up"); err != nil {
			return err
		}
		return run("ip", "addr", "add", localCIDR, "dev", name)
	case "darwin":
		ip, _, err := net.ParseCIDR(localCIDR)
		if err != nil {
			return fmt.Errorf("netcfg: разбор адреса %q: %w", localCIDR, err)
		}
		if peerIP == "" {
			return fmt.Errorf("netcfg(darwin): для utun нужен peerIP")
		}
		return run("ifconfig", name, "inet", ip.String(), peerIP, "mtu", strconv.Itoa(mtu), "up")
	default:
		return fmt.Errorf("netcfg: платформа %s не поддерживается", runtime.GOOS)
	}
}

// DefaultWANInterface определяет интерфейс маршрута по умолчанию (для NAT).
func DefaultWANInterface() (string, error) {
	out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("netcfg: ip route show default: %w", err)
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("netcfg: не найден WAN-интерфейс в %q", strings.TrimSpace(string(out)))
}

// EnableNAT (только Linux/сервер) включает форвардинг и MASQUERADE для подсети
// туннеля через WAN-интерфейс. Если wanIf пуст — определяется автоматически.
// Идемпотентно: правила добавляются только при отсутствии (-C проверка).
func EnableNAT(tunIf, tunSubnet, wanIf string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("netcfg: NAT поддержан только на Linux")
	}
	if wanIf == "" {
		w, err := DefaultWANInterface()
		if err != nil {
			return err
		}
		wanIf = w
	}
	if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	ensure := func(table string, rule ...string) error {
		check := append([]string{"-t", table, "-C"}, rule...)
		if exec.Command("iptables", check...).Run() == nil {
			return nil // правило уже есть
		}
		add := append([]string{"-t", table, "-A"}, rule...)
		return run("iptables", add...)
	}
	if err := ensure("nat", "POSTROUTING", "-s", tunSubnet, "-o", wanIf, "-j", "MASQUERADE"); err != nil {
		return err
	}
	if err := ensure("filter", "FORWARD", "-i", tunIf, "-o", wanIf, "-j", "ACCEPT"); err != nil {
		return err
	}
	return ensure("filter", "FORWARD", "-i", wanIf, "-o", tunIf, "-m", "state",
		"--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
}
