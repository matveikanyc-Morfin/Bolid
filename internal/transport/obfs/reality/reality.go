package reality

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"mirage/internal/transport"
)

const (
	dialTimeout   = 10 * time.Second
	maxFirstBytes = 16384 + 2048 // максимум одной TLS-записи + запас
)

var errNotTLS = errors.New("reality: первый пакет не похож на TLS handshake")

// DialReality (клиент) устанавливает TLS-канал к серверу MIRAGE, пряча в
// SessionID скрытый auth-токен (PSK). Снаружи — обычный TLS 1.3 к SNI.
func DialReality(remote, sni string, psk []byte) (*transport.StreamConn, error) {
	tcp, err := net.DialTimeout("tcp", remote, dialTimeout)
	if err != nil {
		return nil, err
	}
	sid, err := makeAuthSessionID(psk, nowUnix())
	if err != nil {
		tcp.Close()
		return nil, err
	}
	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // подлинность даёт Noise + auth-токен
		NextProtos:         []string{"h2", "http/1.1"},
	}
	uconn := utls.UClient(tcp, cfg, utls.HelloChrome_Auto)
	if err := uconn.BuildHandshakeState(); err != nil {
		tcp.Close()
		return nil, fmt.Errorf("reality: build hello: %w", err)
	}
	// Прячем токен в SessionID (для наблюдателя — обычные 32 случайных байта).
	uconn.HandshakeState.Hello.SessionId = sid
	if err := uconn.MarshalClientHello(); err != nil {
		tcp.Close()
		return nil, fmt.Errorf("reality: marshal hello: %w", err)
	}
	if err := uconn.Handshake(); err != nil {
		tcp.Close()
		return nil, fmt.Errorf("reality: TLS handshake: %w", err)
	}
	return transport.NewStreamConn(uconn), nil
}

// Listener (сервер) принимает соединения: аутентичных клиентов MIRAGE
// обрабатывает как TLS-сервер, остальных прозрачно релеит на реальный dest.
//
// КАЖДОЕ соединение обрабатывается в отдельной горутине: медленный/мёртвый
// клиент не блокирует остальных (важно и для производительности, и для probe-
// resistance — иначе один зонд мог бы заморозить сервер).
type Listener struct {
	ln     net.Listener
	psk    []byte
	dest   string // host:port реального сайта-приманки
	tlsCfg *stdtls.Config
	replay *replayCache

	conns  chan *transport.StreamConn // готовые аутентичные каналы
	closed chan struct{}
	once   sync.Once
}

// Listen поднимает Reality-сервер. dest — реальный сайт для релея зондов;
// certHost — CommonName self-signed серта (виден только аутентичным клиентам).
func Listen(addr string, psk []byte, dest, certHost string) (*Listener, error) {
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
	l := &Listener{
		ln: ln, psk: psk, dest: dest, tlsCfg: cfg, replay: newReplayCache(),
		conns: make(chan *transport.StreamConn), closed: make(chan struct{}),
	}
	go l.acceptLoop()
	return l, nil
}

// LocalAddr — адрес прослушивания.
func (l *Listener) LocalAddr() string { return l.ln.Addr().String() }

func (l *Listener) acceptLoop() {
	for {
		raw, err := l.ln.Accept()
		if err != nil {
			l.markClosed()
			return
		}
		go l.handle(raw)
	}
}

// handle классифицирует одно соединение и либо отдаёт его как аутентичный канал,
// либо прозрачно релеит на dest.
func (l *Listener) handle(raw net.Conn) {
	first, perr := readFirstRecord(raw)
	if perr != nil {
		l.relay(raw, first)
		return
	}
	sid, _, cerr := parseClientHello(first)
	if cerr == nil && verifyAuthSessionID(l.psk, sid, nowUnix(), l.replay) {
		// Наш клиент — перехватываем TLS, реплеим прочитанный ClientHello.
		raw.SetDeadline(time.Now().Add(dialTimeout)) // не зависать на мёртвом клиенте
		pc := &prefixConn{Conn: raw, prefix: first}
		tconn := stdtls.Server(pc, l.tlsCfg)
		if err := tconn.Handshake(); err != nil {
			raw.Close()
			return
		}
		raw.SetDeadline(time.Time{})
		sc := transport.NewStreamConn(tconn)
		select {
		case l.conns <- sc:
		case <-l.closed:
			sc.Close()
		}
		return
	}
	l.relay(raw, first) // зонд/чужой — прозрачно на dest
}

// Accept возвращает следующий аутентичный канал MIRAGE. Зонды/браузеры
// обрабатываются внутри (релей на dest) и здесь не появляются.
func (l *Listener) Accept() (*transport.StreamConn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *Listener) markClosed() { l.once.Do(func() { close(l.closed) }) }

// Close закрывает листенер.
func (l *Listener) Close() error {
	l.markClosed()
	return l.ln.Close()
}

// relay прозрачно проксирует соединение на реальный dest, предварительно
// отправив туда уже прочитанные байты (firstBytes), чтобы зонд получил
// настоящий сайт без отличий.
func (l *Listener) relay(client net.Conn, firstBytes []byte) {
	defer client.Close()
	client.SetReadDeadline(time.Time{}) // снять дедлайн чтения
	up, err := net.DialTimeout("tcp", l.dest, dialTimeout)
	if err != nil {
		return
	}
	defer up.Close()
	if len(firstBytes) > 0 {
		if _, err := up.Write(firstBytes); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, up); done <- struct{}{} }()
	<-done
}

// readFirstRecord читает первую TLS-запись целиком (заголовок + тело).
// Если это не TLS handshake — возвращает прочитанное и errNotTLS (для релея).
func readFirstRecord(c net.Conn) ([]byte, error) {
	c.SetReadDeadline(time.Now().Add(dialTimeout))
	var hdr [5]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x16 { // не handshake record
		return hdr[:], errNotTLS
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n == 0 || n > maxFirstBytes {
		return hdr[:], errNotTLS
	}
	rec := make([]byte, 5+n)
	copy(rec, hdr[:])
	if _, err := io.ReadFull(c, rec[5:]); err != nil {
		return rec, err
	}
	c.SetReadDeadline(time.Time{})
	return rec, nil
}

// prefixConn возвращает сначала заранее прочитанные байты, затем поток соединения.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// selfSigned генерирует временный самоподписанный ECDSA-сертификат.
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
