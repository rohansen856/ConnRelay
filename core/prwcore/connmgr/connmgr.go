// Package connmgr races the data-plane paths for one connection attempt
// (protocol v1 §8): ICE (direct or TURN) starts immediately; the WSS relay
// starts after FallbackDelay, or immediately when the current network is
// known to block UDP. Each path must complete the peer handshake; the first
// to do so wins and the others are closed.
package connmgr

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rohansen856/connrelay/core/prwcore/transport"
)

// Proposed defaults.
const (
	DefaultFallbackDelay = 4 * time.Second
	DefaultTimeout       = 20 * time.Second
)

// ErrTimeout is returned when no path completes in time (connect_timeout).
var ErrTimeout = errors.New("connect_timeout")

// Dialer establishes one transport (including ICE/relay setup).
type Dialer func(ctx context.Context) (transport.Conn, error)

// Options configure a race.
type Options struct {
	ICE           Dialer // nil if unavailable
	WSS           Dialer // nil if unavailable
	FallbackDelay time.Duration
	Timeout       time.Duration
	// UDPBlocked starts the WSS relay at t=0.
	UDPBlocked bool
	// Handshake runs hello + attestation on a fresh transport.
	Handshake func(ctx context.Context, c transport.Conn) error
}

// Attempt records how one path fared.
type Attempt struct {
	Name    string        `json:"name"` // "ice" or "wss"
	Started time.Duration `json:"started_ms"`
	Elapsed time.Duration `json:"elapsed_ms"`
	Err     string        `json:"error,omitempty"`
}

// Report summarises a race for diagnostics.
type Report struct {
	Path     string        `json:"path"` // direct, turn, wss_relay
	Elapsed  time.Duration `json:"elapsed_ms"`
	Attempts []Attempt     `json:"attempts"`
}

type result struct {
	name string
	conn transport.Conn
	err  error
	at   Attempt
}

// Connect runs the race.
func Connect(ctx context.Context, o Options) (transport.Conn, *Report, error) {
	if o.FallbackDelay == 0 {
		o.FallbackDelay = DefaultFallbackDelay
	}
	if o.Timeout == 0 {
		o.Timeout = DefaultTimeout
	}
	if o.ICE == nil && o.WSS == nil {
		return nil, nil, errors.New("connmgr: no paths configured")
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	results := make(chan result, 2)
	launch := func(name string, d Dialer) {
		go func() {
			at := Attempt{Name: name, Started: time.Since(start)}
			c, err := d(ctx)
			if err == nil && o.Handshake != nil {
				if err = o.Handshake(ctx, c); err != nil {
					c.Close()
					c = nil
				}
			}
			at.Elapsed = time.Since(start) - at.Started
			if err != nil {
				at.Err = err.Error()
			}
			results <- result{name, c, err, at}
		}()
	}

	pending := 0
	if o.ICE != nil {
		launch("ice", o.ICE)
		pending++
	}
	wssStarted := false
	startWSS := func() {
		if !wssStarted && o.WSS != nil {
			wssStarted = true
			launch("wss", o.WSS)
			pending++
		}
	}
	if o.UDPBlocked || o.ICE == nil {
		startWSS()
	}
	fallback := time.NewTimer(o.FallbackDelay)
	defer fallback.Stop()

	rep := &Report{}
	var lastErr error
	drain := func(n int) {
		go func() {
			for i := 0; i < n; i++ {
				if r := <-results; r.conn != nil {
					r.conn.Close()
				}
			}
		}()
	}
	for {
		if pending == 0 && (wssStarted || o.WSS == nil) {
			rep.Elapsed = time.Since(start)
			if lastErr == nil {
				lastErr = ErrTimeout
			}
			return nil, rep, lastErr
		}
		select {
		case <-fallback.C:
			startWSS()
		case r := <-results:
			pending--
			rep.Attempts = append(rep.Attempts, r.at)
			if r.err != nil {
				lastErr = r.err
				startWSS() // a failed ICE attempt triggers the fallback at once
				continue
			}
			cancel() // stop the losing path
			drain(pending)
			rep.Path = r.conn.Path()
			rep.Elapsed = time.Since(start)
			return r.conn, rep, nil
		case <-ctx.Done():
			drain(pending)
			rep.Elapsed = time.Since(start)
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, rep, fmt.Errorf("%w (last error: %v)", ErrTimeout, lastErr)
			}
			return nil, rep, ctx.Err()
		}
	}
}
