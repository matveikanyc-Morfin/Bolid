// Package client — встраиваемая клиентская библиотека MIRAGE.
//
// Client держит TUN-устройство открытым и сам поддерживает связь: при обрыве
// транспорта (смена сети Wi-Fi↔LTE, NAT-ребиндинг, рестарт сервера) он
// автоматически переподключается. Сначала пробует РОУМИНГ — переустановить
// транспорт, сохранив сессию (сервер выучивает новый endpoint, рукопожатие не
// нужно); если сервер сессию не узнал — делает полное рукопожатие.
//
// Транспорт создаётся фабрикой Config.Dial (UDP/TLS/Reality), поэтому библиотека
// не привязана к способу доставки и переиспользуется в CLI и в мобильном
// приложении (iOS/Android).
package client

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"mirage/internal/crypto"
	"mirage/internal/session"
	"mirage/internal/transport"
	"mirage/internal/tun"
)

// Dialer создаёт свежий транспорт к серверу (новый сокет/соединение).
type Dialer func() (transport.Conn, error)

// Config — параметры клиента.
type Config struct {
	ServerPub    []byte // статический публичный ключ сервера (32 байта)
	PrivateKey   []byte // статический приватный ключ клиента (32 байта)
	MTU          int    // MTU туннеля (0 → 1380)
	KeepaliveSec int    // интервал keepalive в секундах (0 → 10)
	IdleSec      int    // нет ответа дольше этого → переподключение (0 → 25)
	Dial         Dialer // фабрика транспорта (обязательна)
}

const (
	defaultMTU       = 1380
	defaultKeepalive = 10 * time.Second
	defaultIdle      = 25 * time.Second
	handshakeTimeout = 8 * time.Second
	backoffMin       = 500 * time.Millisecond
	backoffMax       = 20 * time.Second
)

// Client — управляемый клиент MIRAGE с автоматическим переподключением.
type Client struct {
	cfg       Config
	static    crypto.Keypair
	keepalive time.Duration
	idle      time.Duration

	dev tun.Device

	mu   sync.Mutex // сериализует исходящий путь (Seal+Send) и смену conn/sess
	conn transport.Conn
	sess *session.Session

	stop chan struct{}
	once sync.Once
}

func randIndex() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:])
}

// New валидирует конфигурацию и создаёт клиента (без обращения к сети).
func New(cfg Config) (*Client, error) {
	if cfg.Dial == nil {
		return nil, errors.New("client: Config.Dial обязателен")
	}
	static, err := crypto.KeypairFromPrivate(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("client: приватный ключ: %w", err)
	}
	if len(cfg.ServerPub) != crypto.KeyLen {
		return nil, errors.New("client: неверный публичный ключ сервера")
	}
	if cfg.MTU == 0 {
		cfg.MTU = defaultMTU
	}
	c := &Client{
		cfg:       cfg,
		static:    static,
		keepalive: durOr(cfg.KeepaliveSec, defaultKeepalive),
		idle:      durOr(cfg.IdleSec, defaultIdle),
		stop:      make(chan struct{}),
	}
	return c, nil
}

func durOr(sec int, def time.Duration) time.Duration {
	if sec <= 0 {
		return def
	}
	return time.Duration(sec) * time.Second
}

// Run держит туннель живым: подключается, прокачивает трафик и переподключается
// при обрывах. Блокирует до Stop().
func (c *Client) Run(dev tun.Device) error {
	c.dev = dev
	go c.tunReader() // персистентный читатель TUN на всё время работы
	c.supervise()
	return nil
}

// Stop завершает работу клиента.
func (c *Client) Stop() {
	c.once.Do(func() {
		close(c.stop)
		c.mu.Lock()
		if c.conn != nil {
			c.conn.Close()
		}
		c.mu.Unlock()
	})
}

func (c *Client) stopped() bool {
	select {
	case <-c.stop:
		return true
	default:
		return false
	}
}

// sleep ждёт d или Stop; возвращает true, если остановлены.
func (c *Client) sleep(d time.Duration) bool {
	select {
	case <-time.After(d):
		return false
	case <-c.stop:
		return true
	}
}

// tunReader читает TUN всё время жизни клиента и шлёт пакеты в текущую сессию.
// Пока соединения нет — пакеты отбрасываются (как и положено для IP).
func (c *Client) tunReader() {
	buf := make([]byte, c.cfg.MTU+128)
	for {
		n, err := c.dev.ReadPacket(buf)
		if err != nil {
			c.Stop()
			return
		}
		if n == 0 {
			continue
		}
		c.mu.Lock()
		if c.sess != nil && c.conn != nil {
			if rec, e := c.sess.Seal(session.RecordData, buf[:n]); e == nil {
				_ = c.conn.Send(rec) // ошибку обработает rx/idle → реконнект
			}
		}
		c.mu.Unlock()
	}
}

// supervise — цикл подключения/переподключения.
func (c *Client) supervise() {
	backoff := backoffMin
	needHandshake := true // первая попытка — всегда рукопожатие
	for {
		if c.stopped() {
			return
		}
		conn, err := c.cfg.Dial()
		if err != nil {
			if c.sleep(backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		sess := c.currentSess()
		if needHandshake || sess == nil {
			sess, err = c.handshake(conn)
			if err != nil {
				conn.Close()
				if c.sleep(backoff) {
					return
				}
				backoff = nextBackoff(backoff)
				continue
			}
		}

		c.setCurrent(conn, sess)
		c.sendKeepalive() // подсказать серверу новый endpoint (роуминг)

		gotTraffic := c.session(conn, sess)

		c.clearCurrent()
		conn.Close()
		if c.stopped() {
			return
		}
		// Роуминг удался (был трафик) → сессию сохраняем; иначе — переподключаемся
		// с полным рукопожатием.
		needHandshake = !gotTraffic
		if gotTraffic {
			backoff = backoffMin
		} else {
			backoff = nextBackoff(backoff)
		}
		if c.sleep(backoff) {
			return
		}
	}
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > backoffMax {
		return backoffMax
	}
	return d
}

// session прокачивает rx + keepalive + контроль простоя для одного соединения.
// Возвращает true, если за время жизни был получен хоть один валидный пакет
// (значит сессия жива — роуминг состоялся).
func (c *Client) session(conn transport.Conn, sess *session.Session) (gotTraffic bool) {
	var got atomic.Bool
	var lastRecv atomic.Int64
	lastRecv.Store(time.Now().UnixNano())

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			rec, err := conn.Recv()
			if err != nil {
				return
			}
			typ, pl, err := sess.Open(rec)
			if err != nil {
				continue // битый/повтор/чужой
			}
			got.Store(true)
			lastRecv.Store(time.Now().UnixNano())
			switch typ {
			case session.RecordData:
				_, _ = c.dev.WritePacket(pl)
			case session.RecordClose:
				return
			}
		}
	}()

	ka := time.NewTicker(c.keepalive)
	defer ka.Stop()
	check := time.NewTicker(c.keepalive)
	defer check.Stop()

	for {
		select {
		case <-done:
			return got.Load()
		case <-c.stop:
			conn.Close()
			<-done
			return got.Load()
		case <-ka.C:
			c.sendKeepalive()
		case <-check.C:
			if time.Since(time.Unix(0, lastRecv.Load())) > c.idle {
				conn.Close() // мёртвый линк → разбудить rx и выйти
				<-done
				return got.Load()
			}
		}
	}
}

// handshake выполняет рукопожатие Noise_IK поверх conn с таймаутом.
func (c *Client) handshake(conn transport.Conn) (*session.Session, error) {
	type result struct {
		sess *session.Session
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		hs, err := session.NewHandshake(session.Config{
			Initiator:  true,
			Static:     c.static,
			PeerStatic: c.cfg.ServerPub,
			LocalIndex: randIndex(),
			Prologue:   crypto.Prologue(),
		})
		if err != nil {
			ch <- result{nil, err}
			return
		}
		m1, _, err := hs.FramedWrite(nil)
		if err != nil {
			ch <- result{nil, err}
			return
		}
		if err := conn.Send(m1); err != nil {
			ch <- result{nil, err}
			return
		}
		m2, err := conn.Recv()
		if err != nil {
			ch <- result{nil, err}
			return
		}
		_, sess, err := hs.FramedRead(m2)
		if err != nil {
			ch <- result{nil, err}
			return
		}
		if sess == nil {
			ch <- result{nil, errors.New("client: рукопожатие не завершено")}
			return
		}
		ch <- result{sess, nil}
	}()

	select {
	case r := <-ch:
		return r.sess, r.err
	case <-time.After(handshakeTimeout):
		conn.Close() // разбудит Recv в горутине
		return nil, errors.New("client: таймаут рукопожатия")
	case <-c.stop:
		conn.Close()
		return nil, errors.New("client: остановлен")
	}
}

func (c *Client) sendKeepalive() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess == nil || c.conn == nil {
		return
	}
	if rec, err := c.sess.Seal(session.RecordKeepalive, nil); err == nil {
		_ = c.conn.Send(rec)
	}
}

func (c *Client) currentSess() *session.Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sess
}

func (c *Client) setCurrent(conn transport.Conn, sess *session.Session) {
	c.mu.Lock()
	c.conn, c.sess = conn, sess
	c.mu.Unlock()
}

func (c *Client) clearCurrent() {
	c.mu.Lock()
	c.conn, c.sess = nil, nil
	c.mu.Unlock()
}
