// Package tlsobfs реализует профиль обфускации tls-reality, шаг 3a:
// транспорт MIRAGE внутри настоящего TLS 1.3. Снаружи трафик неотличим от HTTPS:
// виден лишь ClientHello (SNI) и ServerHello; сертификат в TLS 1.3 шифруется.
//
//   - Клиент: uTLS с отпечатком Chrome (реалистичный ClientHello).
//   - Сервер: стандартный crypto/tls (на шаге 3a — самоподписанный сертификат).
//   - Подлинность сторон обеспечивает Noise-сессия ВНУТРИ TLS (defense-in-depth),
//     поэтому клиент не обязан доверять CA (3a). Anti-active-probing (Reality:
//     проверка токена в ClientHello + релей зондов на реальный сайт) — шаг 3b.
//
// Возвращается обычный transport.StreamConn, поэтому весь верхний стек MIRAGE
// (Noise-сессия, mux, TUN) работает поверх без изменений.
package tlsobfs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"

	"mirage/internal/transport"
)

// DialTLS устанавливает TLS-канал к remote с указанным SNI и возвращает поток
// MIRAGE-записей, обрамлённых внутри TLS.
func DialTLS(remote, sni string) (*transport.StreamConn, error) {
	tcp, err := net.Dial("tcp", remote)
	if err != nil {
		return nil, err
	}
	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // подлинность даёт Noise внутри (шаг 3a)
		NextProtos:         []string{"h2", "http/1.1"},
	}
	uconn := utls.UClient(tcp, cfg, utls.HelloChrome_Auto)
	if err := uconn.Handshake(); err != nil {
		tcp.Close()
		return nil, fmt.Errorf("tlsobfs: TLS handshake клиента: %w", err)
	}
	return transport.NewStreamConn(uconn), nil
}

// Listener принимает TLS-соединения и отдаёт обрамлённые потоки MIRAGE.
type Listener struct {
	ln  net.Listener
	cfg *stdtls.Config
}

// Listen поднимает TLS-сервер на addr. certHost — CommonName/SAN самоподписанного
// сертификата (шаг 3a); снаружи он не виден (шифруется в TLS 1.3).
func Listen(addr, certHost string) (*Listener, error) {
	cert, err := selfSigned(certHost)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	cfg := &stdtls.Config{
		Certificates: []stdtls.Certificate{cert},
		MinVersion:   stdtls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	return &Listener{ln: ln, cfg: cfg}, nil
}

// LocalAddr возвращает фактический адрес прослушивания.
func (l *Listener) LocalAddr() string { return l.ln.Addr().String() }

// Accept принимает одно TLS-соединение (с завершённым рукопожатием).
func (l *Listener) Accept() (*transport.StreamConn, error) {
	raw, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	tconn := stdtls.Server(raw, l.cfg)
	if err := tconn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tlsobfs: TLS handshake сервера: %w", err)
	}
	return transport.NewStreamConn(tconn), nil
}

// Close закрывает листенер.
func (l *Listener) Close() error { return l.ln.Close() }

// selfSigned генерирует временный самоподписанный ECDSA-сертификат (шаг 3a).
// На шаге 3b сертификат будет заимствоваться у сайта-приманки (Reality).
func selfSigned(host string) (stdtls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return stdtls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return stdtls.Certificate{}, err
	}
	return stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}
