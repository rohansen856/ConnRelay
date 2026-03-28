// Package termstream moves bytes between a terminal process (a PTY running
// "tmux attach" or a plain shell) and one data-plane stream, applying credit
// flow control in both directions (protocol v1 §13).
//
// Output: the pump reserves credit before reading the PTY. With no credit it
// stops reading, so backpressure reaches the program through the kernel PTY
// buffer and tmux; no bytes are dropped and buffering is bounded to one read
// buffer.
//
// Input: phone keystrokes are held until the process has produced its first
// output, because tmux discards input that arrives before the attaching
// client finishes terminal negotiation.
package termstream

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/rohansen856/connrelay/core/prwcore/flow"
	"github.com/rohansen856/connrelay/core/prwcore/frame"
)

// Proc is the terminal process side.
type Proc interface {
	io.ReadWriter
	Resize(cols, rows int) error
}

// Sink delivers frames to the peer.
type Sink func(*frame.Frame) error

// Stream binds one Proc to one stream ID.
type Stream struct {
	ID   uint16
	proc Proc
	sink Sink

	out *flow.Sender   // credit granted by the phone for OUTPUT
	in  *flow.Receiver // credit we grant the phone for INPUT

	ready     chan struct{}
	readyOnce sync.Once
	wmu       sync.Mutex
	seq       atomic.Uint32
	// Stats for tests and diagnostics.
	BytesOut atomic.Int64
	BytesIn  atomic.Int64
}

// New creates a stream. The phone must grant output credit (flow.credit)
// before any output flows.
func New(id uint16, p Proc, sink Sink) *Stream {
	return &Stream{
		ID: id, proc: p, sink: sink,
		out:   flow.NewSender(flow.DefaultOutputWindow),
		in:    flow.NewReceiver(flow.DefaultInputWindow),
		ready: make(chan struct{}),
	}
}

// InitialInputCredit returns the INPUT credit to announce after terminal.ready.
func (s *Stream) InitialInputCredit() int64 { return s.in.Initial() }

// GrantOutput applies a flow.credit from the phone.
func (s *Stream) GrantOutput(n int64) error { return s.out.Grant(n) }

// Run pumps output until the process ends, ctx is cancelled or the sink
// fails. It sends CLOSE_STREAM with FIN when the process output ends.
func (s *Stream) Run(ctx context.Context) error {
	buf := make([]byte, frame.MaxPayload)
	for {
		n, err := s.out.Acquire(ctx, len(buf))
		if err != nil {
			return err
		}
		m, rerr := s.proc.Read(buf[:n])
		s.out.Return(n - m)
		if m > 0 {
			s.readyOnce.Do(func() { close(s.ready) })
			f := &frame.Frame{Type: frame.TypeOutput, StreamID: s.ID, Seq: s.seq.Add(1) - 1, Payload: buf[:m]}
			if err := s.sink(f); err != nil {
				return err
			}
			s.BytesOut.Add(int64(m))
		}
		if rerr != nil {
			_ = s.sink(&frame.Frame{Type: frame.TypeCloseStream, StreamID: s.ID, Flags: frame.FlagFIN})
			if errors.Is(rerr, io.EOF) || isPTYClosed(rerr) {
				return nil
			}
			return rerr
		}
	}
}

// isPTYClosed reports the EIO Linux returns when the PTY slave side closes.
func isPTYClosed(err error) bool { return errors.Is(err, syscall.EIO) }

// ErrInputOverrun is returned when the phone sends more INPUT than granted.
var ErrInputOverrun = errors.New("termstream: input exceeds granted credit")

// Input writes an INPUT payload to the process, waiting for readiness. It
// returns the INPUT credit to re-grant, or 0.
func (s *Stream) Input(ctx context.Context, b []byte) (int64, error) {
	if err := s.in.Received(len(b)); err != nil {
		return 0, ErrInputOverrun
	}
	select {
	case <-s.ready:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	s.wmu.Lock()
	_, err := s.proc.Write(b)
	s.wmu.Unlock()
	if err != nil {
		return 0, err
	}
	s.BytesIn.Add(int64(len(b)))
	return s.in.Consumed(len(b)), nil
}

// Resize forwards a terminal size change.
func (s *Stream) Resize(cols, rows int) error { return s.proc.Resize(cols, rows) }

// Close stops the output pump.
func (s *Stream) Close() { s.out.Close() }
