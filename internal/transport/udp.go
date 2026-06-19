package transport

import (
	"net"
	"net/netip"
	"sync"
)

// --- Клиент UDP (connected socket) ---

// UDPClient — клиентский UDP-канал к фиксированному серверу.
type UDPClient struct {
	conn *net.UDPConn
	buf  []byte
}

// DialUDP открывает UDP-«соединение» к remote (host:port).
func DialUDP(remote string) (*UDPClient, error) {
	raddr, err := net.ResolveUDPAddr("udp", remote)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	return &UDPClient{conn: conn, buf: make([]byte, MaxRecordSize)}, nil
}

func (c *UDPClient) Send(record []byte) error {
	_, err := c.conn.Write(record)
	return err
}

func (c *UDPClient) Recv() ([]byte, error) {
	n, err := c.conn.Read(c.buf)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, c.buf[:n])
	return out, nil
}

func (c *UDPClient) Close() error { return c.conn.Close() }

// --- Сервер UDP (single-peer для MVP) ---

// UDPServer — серверный UDP-сокет, обслуживающий одного пира.
// Endpoint пира выучивается из входящих датаграмм (роуминг, 02 §3.1).
//
// ВНИМАНИЕ: на этом этапе endpoint обновляется при любом приёме. В боевой
// версии обновление допустимо только ПОСЛЕ успешной AEAD-аутентификации
// (иначе сессию можно угнать подделкой src) — будет учтено в Фазе 2.
type UDPServer struct {
	conn *net.UDPConn
	buf  []byte
	mu   sync.Mutex
	peer *net.UDPAddr
}

// ListenUDP поднимает UDP-сокет на addr (например, "0.0.0.0:443" или "127.0.0.1:0").
func ListenUDP(addr string) (*UDPServer, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	return &UDPServer{conn: conn, buf: make([]byte, MaxRecordSize)}, nil
}

// LocalAddr возвращает фактический адрес прослушивания (полезно при порте 0).
func (s *UDPServer) LocalAddr() string { return s.conn.LocalAddr().String() }

func (s *UDPServer) Recv() ([]byte, error) {
	n, addr, err := s.conn.ReadFromUDP(s.buf)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.peer = addr
	s.mu.Unlock()
	out := make([]byte, n)
	copy(out, s.buf[:n])
	return out, nil
}

func (s *UDPServer) Send(record []byte) error {
	s.mu.Lock()
	peer := s.peer
	s.mu.Unlock()
	if peer == nil {
		return net.ErrClosed // ещё не знаем, кому отвечать
	}
	_, err := s.conn.WriteToUDP(record, peer)
	return err
}

// --- Multi-peer API (адрес источника явно) ---
//
// Для сервера с несколькими клиентами одного выученного peer недостаточно:
// нужно знать источник каждого пакета и отвечать конкретному адресу.

// RecvFrom принимает датаграмму и возвращает адрес отправителя.
func (s *UDPServer) RecvFrom() ([]byte, netip.AddrPort, error) {
	n, ap, err := s.conn.ReadFromUDPAddrPort(s.buf)
	if err != nil {
		return nil, ap, err
	}
	out := make([]byte, n)
	copy(out, s.buf[:n])
	return out, ap, nil
}

// SendTo отправляет датаграмму конкретному адресу.
func (s *UDPServer) SendTo(record []byte, addr netip.AddrPort) error {
	_, err := s.conn.WriteToUDPAddrPort(record, addr)
	return err
}

func (s *UDPServer) Close() error { return s.conn.Close() }
