// Package flow implements per-stream, per-direction credit accounting
// (protocol v1 §13). Credit is counted in payload bytes and starts at zero.
package flow

import (
	"context"
	"errors"
	"sync"
)

// Default windows (proposed values, protocol v1 §13).
const (
	DefaultOutputWindow = 256 * 1024
	DefaultInputWindow  = 64 * 1024
)

// ErrClosed is returned by Acquire after Close.
var ErrClosed = errors.New("flow: closed")

// ErrOverGrant is returned when a peer grants more than the window allows.
var ErrOverGrant = errors.New("flow: credit exceeds window")

// Sender tracks credit granted by the peer. A sender with no credit blocks,
// which is what turns into backpressure on the PTY.
type Sender struct {
	mu     sync.Mutex
	credit int64
	max    int64
	closed bool
	wake   chan struct{}
}

// NewSender returns a sender with zero credit. max bounds the outstanding
// credit a peer may grant (0 means no bound).
func NewSender(max int64) *Sender {
	return &Sender{max: max, wake: make(chan struct{})}
}

// Grant adds credit received in a flow.credit message.
func (s *Sender) Grant(n int64) error {
	if n <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.max > 0 && s.credit+n > s.max {
		return ErrOverGrant
	}
	s.credit += n
	close(s.wake)
	s.wake = make(chan struct{})
	return nil
}

// Acquire blocks until at least one byte of credit is available and then
// reserves up to want bytes, returning how many were reserved.
func (s *Sender) Acquire(ctx context.Context, want int) (int, error) {
	if want <= 0 {
		return 0, nil
	}
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return 0, ErrClosed
		}
		if s.credit > 0 {
			n := int64(want)
			if n > s.credit {
				n = s.credit
			}
			s.credit -= n
			s.mu.Unlock()
			return int(n), nil
		}
		wake := s.wake
		s.mu.Unlock()
		select {
		case <-wake:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

// Return gives back credit that was acquired but not used (for example when
// a PTY read returned fewer bytes than reserved).
func (s *Sender) Return(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.credit += int64(n)
	close(s.wake)
	s.wake = make(chan struct{})
}

// Available returns the current credit.
func (s *Sender) Available() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.credit
}

// Close unblocks waiters with ErrClosed.
func (s *Sender) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.wake)
	}
}

// Receiver tracks consumed bytes and decides when to re-grant credit. It
// grants the full window initially and re-grants after half has been consumed.
type Receiver struct {
	mu          sync.Mutex
	window      int64
	outstanding int64 // granted but not yet received
	consumed    int64 // received and consumed since last grant
}

// NewReceiver returns a receiver for the given window.
func NewReceiver(window int64) *Receiver { return &Receiver{window: window} }

// Initial returns the initial grant to send after terminal.ready.
func (r *Receiver) Initial() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.outstanding = r.window
	return r.window
}

// Received records n payload bytes arriving. It returns ErrOverGrant if the
// peer sent more than it was granted (a protocol violation).
func (r *Receiver) Received(n int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if int64(n) > r.outstanding {
		return ErrOverGrant
	}
	r.outstanding -= int64(n)
	return nil
}

// Consumed records n bytes rendered (phone) or written to the PTY (host). It
// returns the credit to grant now, or 0 if no grant is due yet.
func (r *Receiver) Consumed(n int) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.consumed += int64(n)
	if r.consumed < r.window/2 {
		return 0
	}
	g := r.consumed
	r.consumed = 0
	r.outstanding += g
	return g
}
