package reality_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"mirage/internal/transport"
	"mirage/internal/transport/obfs/reality"
)

var pskTest = bytes.Repeat([]byte{0x07}, 32)

func testCert(t *testing.T, cn string) stdtls.Certificate {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	return stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// startDest — фейковый «реальный сайт» (TLS-сервер с сертификатом CN=dest.test),
// который после рукопожатия отдаёт баннер.
func startDest(t *testing.T) string {
	t.Helper()
	cfg := &stdtls.Config{Certificates: []stdtls.Certificate{testCert(t, "dest.test")}}
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("DEST-BANNER"))
				time.Sleep(50 * time.Millisecond)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestRealityAuthenticAndProbe(t *testing.T) {
	dest := startDest(t)

	ln, err := reality.Listen("127.0.0.1:0", pskTest, dest, "www.example-cdn.com")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.LocalAddr()

	// Сервер: в ЦИКЛЕ принимаем аутентичных клиентов (зонды релеятся внутри
	// Accept) и эхо-им записи.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c *transport.StreamConn) {
				defer c.Close()
				for {
					rec, err := c.Recv()
					if err != nil {
						return
					}
					if c.Send(rec) != nil {
						return
					}
				}
			}(c)
		}
	}()

	// 1) Аутентичный клиент MIRAGE (правильный PSK) — должен дойти до нашего сервера.
	conn, err := reality.DialReality(addr, "www.example-cdn.com", pskTest)
	if err != nil {
		t.Fatalf("DialReality: %v", err)
	}
	defer conn.Close()
	msg := []byte("привет через reality")
	if err := conn.Send(msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	got, err := conn.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("эхо не совпало: %q", got)
	}

	// 2) «Зонд» без валидного токена — должен быть прозрачно релеен на dest и
	//    увидеть сертификат реального сайта (CN=dest.test), а не наш.
	probe, err := stdtls.Dial("tcp", addr, &stdtls.Config{
		InsecureSkipVerify: true,
		ServerName:         "www.example-cdn.com",
	})
	if err != nil {
		t.Fatalf("probe dial: %v", err)
	}
	defer probe.Close()
	cn := probe.ConnectionState().PeerCertificates[0].Subject.CommonName
	if cn != "dest.test" {
		t.Fatalf("зонд должен видеть сертификат dest (dest.test), а получил %q", cn)
	}
	buf := make([]byte, len("DEST-BANNER"))
	if _, err := probe.Read(buf); err != nil {
		t.Fatalf("probe read: %v", err)
	}
	if string(buf) != "DEST-BANNER" {
		t.Fatalf("зонд должен получить баннер dest, а получил %q", buf)
	}
}
