package config_test

import (
	"bytes"
	"strings"
	"testing"

	"mirage/config"
	"mirage/internal/crypto"
)

func TestURLRoundtrip(t *testing.T) {
	cKey, _ := crypto.GenerateKeypair()
	sKey, _ := crypto.GenerateKeypair()
	psk, _ := crypto.GenerateKeypair()

	orig := &config.Profile{
		Name:         "мой профиль",
		Endpoint:     "vpn.example.com:5555",
		ServerPub:    sKey.Public,
		PrivateKey:   cKey.Private,
		Address:      "10.7.0.2/24",
		Peer:         "10.7.0.1",
		MTU:          1380,
		KeepaliveSec: 10,
		Transport:    config.TransportReality,
		SNI:          "www.example.com",
		RealityPSK:   psk.Private,
	}

	u := orig.URL()
	if !strings.HasPrefix(u, "mirage://") {
		t.Fatalf("URL не начинается с mirage://: %s", u)
	}

	got, err := config.ParseURL(u)
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	if got.Name != orig.Name || got.Endpoint != orig.Endpoint ||
		got.Address != orig.Address || got.Peer != orig.Peer ||
		got.MTU != orig.MTU || got.KeepaliveSec != orig.KeepaliveSec ||
		got.Transport != orig.Transport || got.SNI != orig.SNI {
		t.Fatalf("поля не совпали: %+v", got)
	}
	if !bytes.Equal(got.PrivateKey, orig.PrivateKey) ||
		!bytes.Equal(got.ServerPub, orig.ServerPub) ||
		!bytes.Equal(got.RealityPSK, orig.RealityPSK) {
		t.Fatal("ключи не совпали после round-trip")
	}
}

func TestURLDefaults(t *testing.T) {
	cKey, _ := crypto.GenerateKeypair()
	sKey, _ := crypto.GenerateKeypair()
	// Минимальный профиль (udp, без опций).
	min := &config.Profile{
		Endpoint:   "1.2.3.4:5555",
		ServerPub:  sKey.Public,
		PrivateKey: cKey.Private,
	}
	got, err := config.ParseURL(min.URL())
	if err != nil {
		t.Fatal(err)
	}
	if got.Transport != config.TransportUDP {
		t.Fatalf("дефолтный transport должен быть udp, получили %q", got.Transport)
	}
	if got.MTU != 1380 || got.KeepaliveSec != 10 {
		t.Fatalf("дефолты mtu/ka не применились: mtu=%d ka=%d", got.MTU, got.KeepaliveSec)
	}
}

func TestParseRejectsBad(t *testing.T) {
	cases := []string{
		"https://example.com",                 // не та схема
		"mirage://@1.2.3.4:5555?pk=abc",        // пустой ключ
		"mirage://notbase64!!@1.2.3.4?pk=xxx",  // битый ключ
	}
	for _, s := range cases {
		if _, err := config.ParseURL(s); err == nil {
			t.Fatalf("ожидалась ошибка для %q", s)
		}
	}
}
