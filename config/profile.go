// Package config — формат провижининга MIRAGE: профиль подключения и его
// сериализация в share-ссылку mirage:// (импорт одной строкой, как vless://).
//
// Формат ссылки:
//
//	mirage://<client_priv_b64u>@<host>:<port>?pk=<server_pub_b64u>
//	         &addr=10.7.0.2/24&peer=10.7.0.1&mtu=1380&ka=10
//	         &t=udp|tls|reality&sni=<sni>&psk=<reality_psk_b64u>#<имя>
//
// userinfo — приватный ключ клиента (его «удостоверение»), pk — публичный ключ
// сервера. Этого достаточно, чтобы клиент подключился.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"mirage/internal/crypto"
)

// Transport — способ доставки.
const (
	TransportUDP     = "udp"
	TransportTLS     = "tls"
	TransportReality = "reality"
)

// Profile — всё необходимое клиенту для подключения.
type Profile struct {
	Name         string // отображаемое имя
	Endpoint     string // host:port сервера
	ServerPub    []byte // публичный ключ сервера (32 байта)
	PrivateKey   []byte // приватный ключ клиента (32 байта) — удостоверение
	Address      string // адрес в туннеле с маской, напр. "10.7.0.2/24"
	Peer         string // адрес другого конца (для utun на macOS), напр. "10.7.0.1"
	MTU          int
	KeepaliveSec int
	Transport    string // udp | tls | reality
	SNI          string // для tls/reality
	RealityPSK   []byte // для reality (опционально)
}

// Validate проверяет обязательные поля.
func (p *Profile) Validate() error {
	if len(p.PrivateKey) != crypto.KeyLen {
		return errors.New("config: неверный приватный ключ клиента")
	}
	if len(p.ServerPub) != crypto.KeyLen {
		return errors.New("config: неверный публичный ключ сервера")
	}
	if p.Endpoint == "" {
		return errors.New("config: пустой endpoint")
	}
	switch p.Transport {
	case "", TransportUDP, TransportTLS, TransportReality:
	default:
		return fmt.Errorf("config: неизвестный transport %q", p.Transport)
	}
	return nil
}

// URL сериализует профиль в строку mirage://.
func (p *Profile) URL() string {
	q := url.Values{}
	q.Set("pk", crypto.EncodeKey(p.ServerPub))
	if p.Address != "" {
		q.Set("addr", p.Address)
	}
	if p.Peer != "" {
		q.Set("peer", p.Peer)
	}
	if p.MTU != 0 {
		q.Set("mtu", strconv.Itoa(p.MTU))
	}
	if p.KeepaliveSec != 0 {
		q.Set("ka", strconv.Itoa(p.KeepaliveSec))
	}
	if p.Transport != "" && p.Transport != TransportUDP {
		q.Set("t", p.Transport)
	}
	if p.SNI != "" {
		q.Set("sni", p.SNI)
	}
	if len(p.RealityPSK) > 0 {
		q.Set("psk", crypto.EncodeKey(p.RealityPSK))
	}
	u := url.URL{
		Scheme:   "mirage",
		User:     url.User(crypto.EncodeKey(p.PrivateKey)),
		Host:     p.Endpoint,
		RawQuery: q.Encode(),
		Fragment: p.Name,
	}
	return u.String()
}

// ParseURL разбирает строку mirage:// в Profile.
func ParseURL(s string) (*Profile, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("config: разбор URL: %w", err)
	}
	if u.Scheme != "mirage" {
		return nil, fmt.Errorf("config: ожидалась схема mirage://, получено %q", u.Scheme)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, errors.New("config: в ссылке нет приватного ключа клиента")
	}
	priv, err := crypto.DecodeKey(u.User.Username())
	if err != nil {
		return nil, fmt.Errorf("config: приватный ключ: %w", err)
	}
	q := u.Query()
	pub, err := crypto.DecodeKey(q.Get("pk"))
	if err != nil {
		return nil, fmt.Errorf("config: pk (публичный ключ сервера): %w", err)
	}

	p := &Profile{
		Name:         u.Fragment,
		Endpoint:     u.Host,
		ServerPub:    pub,
		PrivateKey:   priv,
		Address:      q.Get("addr"),
		Peer:         q.Get("peer"),
		Transport:    orDefault(q.Get("t"), TransportUDP),
		SNI:          q.Get("sni"),
		MTU:          atoiOr(q.Get("mtu"), 1380),
		KeepaliveSec: atoiOr(q.Get("ka"), 10),
	}
	if psk := q.Get("psk"); psk != "" {
		b, err := crypto.DecodeKey(psk)
		if err != nil {
			return nil, fmt.Errorf("config: psk: %w", err)
		}
		p.RealityPSK = b
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func atoiOr(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}
