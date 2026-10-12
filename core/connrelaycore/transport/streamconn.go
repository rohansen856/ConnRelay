package transport

import (
	"net"
	"sync"

	"github.com/rohansen856/connrelay/core/connrelaycore/frame"
)

// StreamConn carries concatenated frames over a reliable byte stream, such as
// the inner TLS 1.3 connection of the WSS relay transport.
type StreamConn struct {
	c         net.Conn
	r         *frame.Reader
	wmu       sync.Mutex
	wbuf      []byte
	transport string
	path      string
	localFP   string
	remoteFP  string
}

// NewStreamConn wraps c. The fingerprints describe the TLS certificates used.
func NewStreamConn(c net.Conn, transport, path, localFP, remoteFP string) *StreamConn {
	return &StreamConn{
		c: c, r: frame.NewReader(c), wbuf: make([]byte, 0, frame.MaxFrameSize),
		transport: transport, path: path, localFP: localFP, remoteFP: remoteFP,
	}
}

func (s *StreamConn) Send(f *frame.Frame) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	b, err := frame.AppendEncode(s.wbuf[:0], f)
	if err != nil {
		return err
	}
	_, err = s.c.Write(b)
	return err
}

func (s *StreamConn) Recv() (*frame.Frame, error) {
	f, err := s.r.Next()
	if err != nil {
		return nil, err
	}
	f.Payload = append([]byte(nil), f.Payload...)
	return f, nil
}

func (s *StreamConn) Transport() string    { return s.transport }
func (s *StreamConn) Path() string         { return s.path }
func (s *StreamConn) LocalCertFP() string  { return s.localFP }
func (s *StreamConn) RemoteCertFP() string { return s.remoteFP }
func (s *StreamConn) Close() error         { return s.c.Close() }
