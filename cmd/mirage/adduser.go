package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"mirage/config"
	"mirage/internal/crypto"
)

// cmdAddUser провижинит нового пользователя: генерирует клиентский ключ,
// дописывает его в peers-файл сервера и печатает готовую ссылку mirage:// для
// импорта в клиент/приложение.
func cmdAddUser(args []string) {
	fs := flag.NewFlagSet("adduser", flag.ExitOnError)
	peersFile := fs.String("peers", "", "файл пиров сервера (куда добавить пользователя)")
	serverPub := fs.String("server", "", "публичный ключ сервера (base64url)")
	endpoint := fs.String("endpoint", "", "адрес сервера host:port (для ссылки)")
	addr := fs.String("addr", "", "адрес клиента в туннеле с маской, напр. 10.7.0.2/24")
	peer := fs.String("peer", "", "адрес сервера в туннеле (для utun на macOS), напр. 10.7.0.1")
	name := fs.String("name", "", "имя пользователя")
	transport := fs.String("t", "udp", "транспорт: udp|tls|reality")
	sni := fs.String("sni", "", "SNI (для tls/reality)")
	realityPSK := fs.String("reality-psk", "", "Reality PSK (base64url)")
	mtu := fs.Int("mtu", 1380, "MTU")
	ka := fs.Int("ka", 10, "keepalive, сек")
	_ = fs.Parse(args)

	if *peersFile == "" || *serverPub == "" || *endpoint == "" || *addr == "" {
		fail("нужны -peers, -server, -endpoint, -addr")
	}
	sPub, err := crypto.DecodeKey(*serverPub)
	if err != nil {
		fail("-server: %v", err)
	}
	prefix, err := netip.ParsePrefix(*addr)
	if err != nil {
		fail("-addr (ожидался CIDR, напр. 10.7.0.2/24): %v", err)
	}
	tunIP := prefix.Addr()

	// Генерируем удостоверение клиента.
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		fail("генерация ключей: %v", err)
	}

	// Дописываем пира в файл сервера: "pubkey ip [name]".
	line := crypto.EncodeKey(kp.Public) + " " + tunIP.String()
	if *name != "" {
		line += " " + strings.ReplaceAll(*name, " ", "_")
	}
	f, err := os.OpenFile(*peersFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fail("открытие peers-файла: %v", err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		f.Close()
		fail("запись peers: %v", err)
	}
	f.Close()

	var psk []byte
	if *realityPSK != "" {
		if psk, err = crypto.DecodeKey(*realityPSK); err != nil {
			fail("-reality-psk: %v", err)
		}
	}
	prof := &config.Profile{
		Name:         *name,
		Endpoint:     *endpoint,
		ServerPub:    sPub,
		PrivateKey:   kp.Private,
		Address:      *addr,
		Peer:         *peer,
		MTU:          *mtu,
		KeepaliveSec: *ka,
		Transport:    *transport,
		SNI:          *sni,
		RealityPSK:   psk,
	}
	if err := prof.Validate(); err != nil {
		fail("%v", err)
	}

	fmt.Printf("Пользователь %q добавлен в %s (ip %s).\n", *name, *peersFile, tunIP)
	fmt.Println("Перезапустите сервер, чтобы применить.")
	fmt.Println("Ссылка для клиента (импортировать в приложение/CLI):")
	fmt.Println(prof.URL())
}
