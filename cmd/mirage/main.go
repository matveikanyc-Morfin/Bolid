// Командная утилита mirage — клиент и сервер протокола MIRAGE (Фаза 1).
//
// Подкоманды:
//
//	mirage genkey
//	mirage server -listen 0.0.0.0:5555 -key <priv> [-tun -tun-addr 10.7.0.1/24 -nat]
//	mirage client -connect host:5555 -server <pub> -key <priv> [-tun -tun-addr 10.7.0.2/24 -peer 10.7.0.1]
//
// Без -tun сервер/клиент работают в режиме «эхо поверх сессии» (отладка крипто).
// С -tun поднимается настоящий L3-туннель через TUN-устройство.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"mirage/client"
	"mirage/config"
	"mirage/internal/crypto"
	"mirage/internal/netcfg"
	"mirage/internal/session"
	"mirage/internal/transport"
	"mirage/internal/transport/obfs/reality"
	"mirage/internal/transport/obfs/tlsobfs"
	"mirage/internal/tun"
	"mirage/server"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "genkey":
		cmdGenkey()
	case "server":
		cmdServer(os.Args[2:])
	case "client":
		cmdClient(os.Args[2:])
	case "adduser":
		cmdAddUser(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `mirage — MIRAGE VPN

  mirage genkey
  mirage server  -listen ADDR -key PRIV [-tun -tun-addr CIDR -nat] [-peers FILE]
  mirage adduser -peers FILE -server PUB -endpoint HOST:PORT -addr CIDR [-name N]
  mirage client  -url mirage://...   |   -connect ADDR -server PUB -key PRIV [-tun ...]
`)
	os.Exit(2)
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ошибка: "+format+"\n", a...)
	os.Exit(1)
}

func randIndex() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:])
}

func cmdGenkey() {
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		fail("генерация ключей: %v", err)
	}
	fmt.Printf("private = %s\n", crypto.EncodeKey(kp.Private))
	fmt.Printf("public  = %s\n", crypto.EncodeKey(kp.Public))
}

// subnetCIDR возвращает сетевой адрес подсети из адреса с маской
// ("10.7.0.1/24" → "10.7.0.0/24").
func subnetCIDR(addrCIDR string) (string, error) {
	_, ipnet, err := net.ParseCIDR(addrCIDR)
	if err != nil {
		return "", err
	}
	return ipnet.String(), nil
}

func cmdServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", "0.0.0.0:5555", "адрес прослушивания")
	keyStr := fs.String("key", "", "приватный ключ сервера (base64url)")
	keyFile := fs.String("key-file", "", "файл с приватным ключом сервера")
	useTun := fs.Bool("tun", false, "включить L3-туннель (TUN)")
	useTLS := fs.Bool("tls", false, "транспорт TLS (профиль tls-reality, шаг 3a) вместо UDP")
	useReality := fs.Bool("reality", false, "профиль Reality (3b): anti-probe, релей зондов на dest")
	dest := fs.String("dest", "www.microsoft.com:443", "реальный сайт-приманка для релея (Reality)")
	realityPSK := fs.String("reality-psk", "", "PSK Reality (base64url, 32 байта)")
	realityPSKFile := fs.String("reality-psk-file", "", "файл с PSK Reality")
	certHost := fs.String("cert-host", "www.microsoft.com", "CommonName self-signed серта (TLS)")
	tunName := fs.String("tun-name", "mirage0", "имя TUN-интерфейса (Linux)")
	tunAddr := fs.String("tun-addr", "10.7.0.1/24", "адрес интерфейса с маской")
	mtu := fs.Int("mtu", 1380, "MTU туннеля")
	doNAT := fs.Bool("nat", false, "включить NAT (MASQUERADE) для выхода в интернет")
	wan := fs.String("wan", "", "WAN-интерфейс для NAT (пусто = автоопределение)")
	peersFile := fs.String("peers", "", "файл пиров для multi-peer (UDP): 'pubkey ip [name]'")
	_ = fs.Parse(args)

	static := loadKey(*keyStr, *keyFile)

	if *useTun {
		dev := setupTun(*tunName, *tunAddr, *mtu, *doNAT, *wan)
		defer dev.Close()
		switch {
		case *useReality:
			psk := loadPSK(*realityPSK, *realityPSKFile)
			ln, err := reality.Listen(*listen, psk, *dest, *certHost)
			if err != nil {
				fail("reality listen: %v", err)
			}
			fmt.Printf("[server] слушаю Reality %s (dest=%s), зонды → приманка\n", ln.LocalAddr(), *dest)
			accept := func() (transport.Conn, error) {
				c, err := ln.Accept()
				if err != nil {
					return nil, err
				}
				return c, nil
			}
			if err := runServerTunnelTLS(static, accept, dev); err != nil {
				fail("туннель: %v", err)
			}
		case *useTLS:
			ln, err := tlsobfs.Listen(*listen, *certHost)
			if err != nil {
				fail("tls listen: %v", err)
			}
			fmt.Printf("[server] слушаю TLS %s (профиль tls-reality 3a)\n", ln.LocalAddr())
			accept := func() (transport.Conn, error) {
				c, err := ln.Accept()
				if err != nil {
					return nil, err
				}
				return c, nil
			}
			if err := runServerTunnelTLS(static, accept, dev); err != nil {
				fail("туннель: %v", err)
			}
		default:
			srv, err := transport.ListenUDP(*listen)
			if err != nil {
				fail("listen: %v", err)
			}
			fmt.Printf("[server] слушаю UDP %s\n", srv.LocalAddr())
			if *peersFile != "" {
				peers, err := loadPeers(*peersFile)
				if err != nil {
					fail("peers: %v", err)
				}
				msrv, err := server.New(static.Private, peers)
				if err != nil {
					fail("multi-peer: %v", err)
				}
				fmt.Printf("[server] multi-peer: %d пир(ов)\n", len(peers))
				if err := msrv.Serve(srv, dev); err != nil {
					fail("туннель: %v", err)
				}
			} else if err := runServerTunnel(static, srv, dev); err != nil {
				fail("туннель: %v", err)
			}
		}
		return
	}

	// Отладочный эхо-режим (только UDP).
	srv, err := transport.ListenUDP(*listen)
	if err != nil {
		fail("listen: %v", err)
	}
	fmt.Printf("[server] слушаю UDP %s\n", srv.LocalAddr())
	serveEcho(static, srv)
}

// setupTun открывает и настраивает TUN-интерфейс (+ NAT на сервере).
func setupTun(name, addr string, mtu int, doNAT bool, wan string) tun.Device {
	dev, err := tun.Open(name, mtu)
	if err != nil {
		fail("открытие TUN: %v", err)
	}
	if err := netcfg.ConfigureInterface(dev.Name(), addr, "", mtu); err != nil {
		fail("настройка интерфейса: %v", err)
	}
	if doNAT {
		subnet, err := subnetCIDR(addr)
		if err != nil {
			fail("подсеть: %v", err)
		}
		if err := netcfg.EnableNAT(dev.Name(), subnet, wan); err != nil {
			fail("NAT: %v", err)
		}
		fmt.Printf("[server] NAT включён для %s\n", subnet)
	}
	fmt.Printf("[server] туннель: %s (%s, mtu %d), жду клиента...\n", dev.Name(), addr, mtu)
	return dev
}

// serveEcho — отладочный режим: одно рукопожатие, затем эхо записей.
func serveEcho(static crypto.Keypair, srv *transport.UDPServer) {
	hs, err := session.NewHandshake(session.Config{
		Initiator: false, Static: static,
		LocalIndex: randIndex(), Prologue: crypto.Prologue(),
	})
	if err != nil {
		fail("handshake init: %v", err)
	}
	m1, err := srv.Recv()
	if err != nil {
		fail("recv msg1: %v", err)
	}
	if _, _, err := hs.FramedRead(m1); err != nil {
		fail("read msg1: %v", err)
	}
	m2, sess, err := hs.FramedWrite(nil)
	if err != nil {
		fail("write msg2: %v", err)
	}
	if err := srv.Send(m2); err != nil {
		fail("send msg2: %v", err)
	}
	fmt.Println("[server] рукопожатие завершено")
	echoLoop(sess, srv)
}

func echoLoop(sess *session.Session, srv *transport.UDPServer) {
	for {
		rec, err := srv.Recv()
		if err != nil {
			fail("recv: %v", err)
		}
		typ, pl, err := sess.Open(rec)
		if err != nil {
			fmt.Printf("[server] отброшен пакет: %v\n", err)
			continue
		}
		if typ == session.RecordClose {
			return
		}
		fmt.Printf("[server] получено: %q\n", pl)
		echo, _ := sess.Seal(session.RecordData, pl)
		_ = srv.Send(echo)
	}
}

func cmdClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	connect := fs.String("connect", "127.0.0.1:5555", "адрес сервера UDP")
	keyStr := fs.String("key", "", "приватный ключ клиента (base64url)")
	keyFile := fs.String("key-file", "", "файл с приватным ключом клиента")
	serverPub := fs.String("server", "", "публичный ключ сервера (base64url)")
	useTun := fs.Bool("tun", false, "включить L3-туннель (TUN)")
	tunName := fs.String("tun-name", "mirage0", "имя TUN-интерфейса (Linux)")
	tunAddr := fs.String("tun-addr", "10.7.0.2/24", "адрес интерфейса с маской")
	peer := fs.String("peer", "10.7.0.1", "адрес другого конца (для utun на macOS)")
	mtu := fs.Int("mtu", 1380, "MTU туннеля")
	keepalive := fs.Duration("keepalive", 10*time.Second, "интервал keepalive (0 = выкл)")
	msg := fs.String("msg", "", "[эхо-режим] одно сообщение; иначе stdin")
	useTLS := fs.Bool("tls", false, "транспорт TLS (профиль tls-reality 3a) вместо UDP")
	useReality := fs.Bool("reality", false, "профиль Reality (3b)")
	realityPSK := fs.String("reality-psk", "", "PSK Reality (base64url, 32 байта)")
	sni := fs.String("sni", "www.microsoft.com", "SNI для TLS/Reality профиля")
	urlStr := fs.String("url", "", "профиль mirage://... (переопределяет флаги подключения)")
	_ = fs.Parse(args)

	// Импорт профиля из ссылки mirage:// — заполняет параметры подключения.
	if *urlStr != "" {
		prof, err := config.ParseURL(*urlStr)
		if err != nil {
			fail("-url: %v", err)
		}
		*connect = prof.Endpoint
		*serverPub = crypto.EncodeKey(prof.ServerPub)
		*keyStr = crypto.EncodeKey(prof.PrivateKey)
		*keyFile = ""
		*useTun = true
		if prof.Address != "" {
			*tunAddr = prof.Address
		}
		if prof.Peer != "" {
			*peer = prof.Peer
		}
		if prof.MTU != 0 {
			*mtu = prof.MTU
		}
		if prof.KeepaliveSec != 0 {
			*keepalive = time.Duration(prof.KeepaliveSec) * time.Second
		}
		if prof.SNI != "" {
			*sni = prof.SNI
		}
		switch prof.Transport {
		case config.TransportTLS:
			*useTLS = true
		case config.TransportReality:
			*useReality = true
			if len(prof.RealityPSK) > 0 {
				*realityPSK = crypto.EncodeKey(prof.RealityPSK)
			}
		}
	}

	static := loadKey(*keyStr, *keyFile)
	peerPub, err := crypto.DecodeKey(*serverPub)
	if err != nil {
		fail("-server: %v", err)
	}

	dial := func() (transport.Conn, error) {
		switch {
		case *useReality:
			c, err := reality.DialReality(*connect, *sni, loadPSK(*realityPSK, ""))
			if err != nil {
				return nil, err
			}
			return c, nil
		case *useTLS:
			c, err := tlsobfs.DialTLS(*connect, *sni)
			if err != nil {
				return nil, err
			}
			return c, nil
		default:
			c, err := transport.DialUDP(*connect)
			if err != nil {
				return nil, err
			}
			return c, nil
		}
	}

	if *useTun {
		c, err := client.New(client.Config{
			ServerPub:    peerPub,
			PrivateKey:   static.Private,
			MTU:          *mtu,
			KeepaliveSec: int(keepalive.Seconds()),
			Dial:         dial,
		})
		if err != nil {
			fail("%v", err)
		}
		dev, err := tun.Open(*tunName, *mtu)
		if err != nil {
			fail("открытие TUN: %v", err)
		}
		defer dev.Close()
		if err := netcfg.ConfigureInterface(dev.Name(), *tunAddr, *peer, *mtu); err != nil {
			fail("настройка интерфейса: %v", err)
		}
		fmt.Printf("[client] туннель: %s (%s, mtu %d), подключаюсь (авто-реконнект включён)...\n", dev.Name(), *tunAddr, *mtu)
		fmt.Println("[client] маршрутизацию трафика в туннель настройте отдельно (см. docs)")
		if err := c.Run(dev); err != nil {
			fail("туннель: %v", err)
		}
		return
	}

	// Эхо-режим (отладка): одно соединение, рукопожатие вручную.
	conn, err := dial()
	if err != nil {
		fail("dial: %v", err)
	}
	defer conn.Close()
	hs, err := session.NewHandshake(session.Config{
		Initiator: true, Static: static, PeerStatic: peerPub,
		LocalIndex: randIndex(), Prologue: crypto.Prologue(),
	})
	if err != nil {
		fail("handshake init: %v", err)
	}
	m1, _, err := hs.FramedWrite(nil)
	if err != nil {
		fail("write msg1: %v", err)
	}
	if err := conn.Send(m1); err != nil {
		fail("send msg1: %v", err)
	}
	m2, err := conn.Recv()
	if err != nil {
		fail("recv msg2: %v", err)
	}
	_, sess, err := hs.FramedRead(m2)
	if err != nil {
		fail("read msg2: %v", err)
	}
	if sess == nil {
		fail("сессия не установлена")
	}
	fmt.Println("[client] рукопожатие завершено")
	echoClient(sess, conn, *msg)
}

func echoClient(sess *session.Session, conn transport.Conn, msg string) {
	send := func(text string) {
		rec, _ := sess.Seal(session.RecordData, []byte(text))
		if err := conn.Send(rec); err != nil {
			fail("send: %v", err)
		}
		back, err := conn.Recv()
		if err != nil {
			fail("recv echo: %v", err)
		}
		_, pl, err := sess.Open(back)
		if err != nil {
			fail("open echo: %v", err)
		}
		fmt.Printf("[client] эхо: %q\n", pl)
	}
	if msg != "" {
		send(msg)
		return
	}
	fmt.Println("[client] вводите строки (Ctrl-D — выход):")
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		send(sc.Text())
	}
}

// loadPSK декодирует Reality-PSK из флага (base64url, 32 байта) или из файла.
func loadPSK(b64, file string) []byte {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			fail("-reality-psk-file: %v", err)
		}
		b64 = strings.TrimSpace(string(data))
	}
	if b64 == "" {
		fail("нужен -reality-psk или -reality-psk-file")
	}
	psk, err := crypto.DecodeKey(b64)
	if err != nil {
		fail("reality-psk: %v", err)
	}
	return psk
}

// loadKey читает приватный ключ из флага -key (base64url) или из файла -key-file.
// Файл предпочтительнее: ключ не виден в списке процессов.
func loadKey(b64, file string) crypto.Keypair {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			fail("-key-file: %v", err)
		}
		b64 = strings.TrimSpace(string(data))
	}
	if b64 == "" {
		fail("нужен -key или -key-file")
	}
	priv, err := crypto.DecodeKey(b64)
	if err != nil {
		fail("приватный ключ: %v", err)
	}
	kp, err := crypto.KeypairFromPrivate(priv)
	if err != nil {
		fail("приватный ключ: %v", err)
	}
	return kp
}
