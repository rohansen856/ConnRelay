// Package control defines the JSON control-message envelope carried in
// CONTROL frames (protocol v1 §11).
package control

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/rohansen856/connrelay/core/prwcore/frame"
)

// MaxMessage bounds one control message.
const MaxMessage = 16 * 1024

// Message types.
const (
	TypeHello            = "hello"
	TypePeerAttest       = "peer.attest"
	TypeIdentityVerified = "peer.identity_verified"
	TypeTerminalList     = "terminal.list"
	TypeTerminalListRes  = "terminal.list.result"
	TypeTerminalOpen     = "terminal.open"
	TypeTerminalAttach   = "terminal.attach"
	TypeTerminalReady    = "terminal.ready"
	TypeTerminalResize   = "terminal.resize"
	TypeTerminalDetach   = "terminal.detach"
	TypeTerminalTerm     = "terminal.terminate"
	TypeTerminalExit     = "terminal.exit"
	TypeTerminalError    = "terminal.error"
	TypeFlowCredit       = "flow.credit"
	TypePing             = "ping"
	TypePong             = "pong"
	TypeSessionRevoked   = "session.revoked"
)

// Envelope is one control message. Unknown fields are ignored by receivers.
type Envelope struct {
	V                 int             `json:"v"`
	Type              string          `json:"type"`
	RequestID         string          `json:"request_id,omitempty"`
	TerminalSessionID string          `json:"terminal_session_id,omitempty"`
	Payload           json.RawMessage `json:"payload,omitempty"`
}

// NewRequestID returns a random request identifier.
func NewRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// New builds an envelope with a JSON-encoded payload.
func New(typ string, payload any) (*Envelope, error) {
	e := &Envelope{V: 1, Type: typ, RequestID: NewRequestID()}
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		e.Payload = b
	}
	return e, nil
}

// Frame encodes the envelope as a CONTROL frame.
func (e *Envelope) Frame() (*frame.Frame, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxMessage {
		return nil, fmt.Errorf("%w: control message %d bytes", frame.ErrProtocol, len(b))
	}
	return &frame.Frame{Type: frame.TypeControl, Payload: b}, nil
}

// Decode parses a CONTROL frame.
func Decode(f *frame.Frame) (*Envelope, error) {
	if f.Type != frame.TypeControl {
		return nil, fmt.Errorf("%w: not a control frame", frame.ErrProtocol)
	}
	if len(f.Payload) > MaxMessage {
		return nil, fmt.Errorf("%w: control message too large", frame.ErrProtocol)
	}
	var e Envelope
	if err := json.Unmarshal(f.Payload, &e); err != nil {
		return nil, fmt.Errorf("%w: control json: %v", frame.ErrProtocol, err)
	}
	if e.V != 1 || e.Type == "" {
		return nil, fmt.Errorf("%w: bad envelope", frame.ErrProtocol)
	}
	return &e, nil
}

// Unmarshal decodes the payload into v.
func (e *Envelope) Unmarshal(v any) error {
	if len(e.Payload) == 0 {
		return nil
	}
	if err := json.Unmarshal(e.Payload, v); err != nil {
		return fmt.Errorf("%w: %s payload: %v", frame.ErrProtocol, e.Type, err)
	}
	return nil
}

// Hello negotiates the protocol version.
type Hello struct {
	PVMin    int      `json:"pv_min"`
	PVMax    int      `json:"pv_max"`
	Impl     string   `json:"impl"`
	Features []string `json:"features,omitempty"`
}

// PeerAttest carries the attestation JWS (and the ticket, from the phone).
type PeerAttest struct {
	JWS    string `json:"jws"`
	Ticket string `json:"ticket,omitempty"`
}

// FlowCredit grants payload bytes on a stream.
type FlowCredit struct {
	StreamID uint16 `json:"stream_id"`
	Bytes    int64  `json:"bytes"`
}
