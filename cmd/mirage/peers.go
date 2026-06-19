package main

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"mirage/internal/crypto"
	"mirage/server"
)

// loadPeers читает файл пиров для multi-peer режима. Формат — по строке на пира:
//
//	<public_key_base64url> <tunnel_ip> [имя]
//	# строки с # и пустые игнорируются
//
// Пример:
//
//	<public_key_base64url> 10.7.0.2 laptop
func loadPeers(path string) ([]server.Peer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var peers []server.Peer
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) < 2 {
			return nil, fmt.Errorf("peers:%d: ожидается 'pubkey ip [name]'", line)
		}
		pub, err := crypto.DecodeKey(fields[0])
		if err != nil {
			return nil, fmt.Errorf("peers:%d: ключ: %w", line, err)
		}
		ip, err := netip.ParseAddr(fields[1])
		if err != nil {
			return nil, fmt.Errorf("peers:%d: адрес %q: %w", line, fields[1], err)
		}
		name := ""
		if len(fields) >= 3 {
			name = fields[2]
		}
		peers = append(peers, server.Peer{PublicKey: pub, TunnelIP: ip, Name: name})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(peers) == 0 {
		return nil, fmt.Errorf("peers: файл %s пуст", path)
	}
	return peers, nil
}
