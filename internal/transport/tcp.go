package transport

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// StreamConn оборачивает потоковое соединение (TCP) обрамлением записей:
//
//	[len:2 BE][record]
//
// Длина пока в открытом виде. В Фазе 2/3 длина будет шифроваться (схема
// Shadowsocks-2022), чтобы по потоку не читались границы записей.
type StreamConn struct {
	conn net.Conn
	r    *bufio.Reader
	hdr  [2]byte
}

// NewStreamConn оборачивает уже установленное соединение.
func NewStreamConn(conn net.Conn) *StreamConn {
	return &StreamConn{conn: conn, r: bufio.NewReader(conn)}
}

// DialTCP подключается к remote и возвращает обрамлённый канал.
func DialTCP(remote string) (*StreamConn, error) {
	conn, err := net.Dial("tcp", remote)
	if err != nil {
		return nil, err
	}
	return NewStreamConn(conn), nil
}

var errRecordTooLarge = errors.New("transport: запись превышает максимум")

func (s *StreamConn) Send(record []byte) error {
	if len(record) > MaxRecordSize {
		return errRecordTooLarge
	}
	binary.BigEndian.PutUint16(s.hdr[:], uint16(len(record)))
	if _, err := s.conn.Write(s.hdr[:]); err != nil {
		return err
	}
	_, err := s.conn.Write(record)
	return err
}

func (s *StreamConn) Recv() ([]byte, error) {
	if _, err := io.ReadFull(s.r, s.hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(s.hdr[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(s.r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (s *StreamConn) Close() error { return s.conn.Close() }

// TCPListener принимает входящие TCP-соединения и отдаёт обрамлённые каналы.
type TCPListener struct{ ln net.Listener }

// ListenTCP начинает слушать TCP на addr.
func ListenTCP(addr string) (*TCPListener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &TCPListener{ln: ln}, nil
}

// LocalAddr возвращает фактический адрес прослушивания.
func (l *TCPListener) LocalAddr() string { return l.ln.Addr().String() }

// Accept принимает одно соединение.
func (l *TCPListener) Accept() (*StreamConn, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	return NewStreamConn(conn), nil
}

func (l *TCPListener) Close() error { return l.ln.Close() }
