// Package mobile — тонкая обёртка над client для сборки под iOS/Android через
// gomobile (`gomobile bind`). API использует только gomobile-совместимые типы
// (int, string, error, привязываемые структуры), без срезов-срезов/каналов/функций.
//
// На iOS NEPacketTunnelProvider создаёт utun и отдаёт его файловый дескриптор;
// Swift вызывает Start(fd, ...) и затем Stop(). Чтение/запись пакетов выполняет
// сам Go-код через переданный fd.
package mobile

import (
	"fmt"

	"mirage/client"
	"mirage/internal/crypto"
	"mirage/internal/transport"
	"mirage/internal/tun"
)

// Tunnel — активный туннель MIRAGE, управляемый из приложения.
type Tunnel struct {
	c   *client.Client
	dev tun.Device
}

// Start поднимает туннель на готовом дескрипторе TUN/utun.
//
//	tunFd        — fd от системного VPN-фреймворка (NEPacketTunnelProvider).
//	endpoint     — адрес сервера "host:port".
//	serverPubB64 — публичный ключ сервера (base64url).
//	privKeyB64   — приватный ключ клиента (base64url).
//	mtu          — MTU (например, 1380).
//	keepaliveSec — интервал keepalive в секундах (0 — выкл).
func Start(tunFd int, endpoint, serverPubB64, privKeyB64 string, mtu, keepaliveSec int) (*Tunnel, error) {
	serverPub, err := crypto.DecodeKey(serverPubB64)
	if err != nil {
		return nil, fmt.Errorf("mobile: server pub: %w", err)
	}
	priv, err := crypto.DecodeKey(privKeyB64)
	if err != nil {
		return nil, fmt.Errorf("mobile: private key: %w", err)
	}
	dial := func() (transport.Conn, error) {
		conn, err := transport.DialUDP(endpoint)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	c, err := client.New(client.Config{
		ServerPub:    serverPub,
		PrivateKey:   priv,
		MTU:          mtu,
		KeepaliveSec: keepaliveSec,
		Dial:         dial,
	})
	if err != nil {
		return nil, err
	}
	dev, err := tun.FromFD(tunFd, mtu)
	if err != nil {
		return nil, fmt.Errorf("mobile: tun fd: %w", err)
	}
	t := &Tunnel{c: c, dev: dev}
	// Run подключается и держит связь сам (с авто-реконнектом) в фоне.
	go func() { _ = c.Run(dev) }()
	return t, nil
}

// Stop останавливает туннель и освобождает ресурсы.
func (t *Tunnel) Stop() {
	if t.c != nil {
		t.c.Stop()
	}
	if t.dev != nil {
		t.dev.Close()
	}
}

// GenerateKeypair создаёт новую пару ключей; возвращает "private\npublic"
// (base64url). Удобно для генерации ключей внутри приложения.
func GenerateKeypair() (string, error) {
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		return "", err
	}
	return crypto.EncodeKey(kp.Private) + "\n" + crypto.EncodeKey(kp.Public), nil
}
