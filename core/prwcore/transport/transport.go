// Package transport defines the frame-level connection shared by the WebRTC
// and WSS-relay transports.
package transport

import (
	"errors"

	"github.com/rohansen856/connrelay/core/prwcore/frame"
)

// Paths reported to the control plane and shown in the UI.
const (
	PathDirect   = "direct"
	PathTURN     = "turn"
	PathWSSRelay = "wss_relay"
)

// ErrClosed is returned after Close.
var ErrClosed = errors.New("transport: closed")

// Conn carries PRW frames between two peers over an encrypted channel.
//
// Send is safe for concurrent use. Recv must be called from one goroutine;
// the returned frame's payload is owned by the caller.
type Conn interface {
	Send(f *frame.Frame) error
	Recv() (*frame.Frame, error)
	// Transport is "dtls" or "tls13" (the attestation transport field).
	Transport() string
	// Path is one of PathDirect, PathTURN or PathWSSRelay.
	Path() string
	// LocalCertFP and RemoteCertFP are SHA-256 fingerprints (hex) of the
	// certificates actually used on this connection.
	LocalCertFP() string
	RemoteCertFP() string
	Close() error
}
