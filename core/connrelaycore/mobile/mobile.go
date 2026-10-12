// Package mobile is the gomobile-bound API of the shared core for the phone
// app. It exposes only gomobile-compatible types (strings, ints, []byte,
// interfaces) and keeps all protocol and crypto encoding in Go, so the app
// never re-implements attestation, framing or flow control.
//
// Blocking calls (Connect, Open, Attach, List, Terminate, Input) must be made
// off the UI thread. Events and output arrive on Go goroutines.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/rohansen856/connrelay/core/connrelaycore/attest"
	"github.com/rohansen856/connrelay/core/connrelaycore/client"
	"github.com/rohansen856/connrelay/core/connrelaycore/termclient"
)

// Signer is implemented by the platform with a non-exportable P-256 key
// (Android Keystore / iOS Secure Enclave).
type Signer interface {
	PublicKeySPKI() ([]byte, error)
	// SignDER signs an already-hashed SHA-256 digest; returns ASN.1 DER.
	SignDER(digest []byte) ([]byte, error)
}

// Events receives output and lifecycle events.
type Events interface {
	// OnOutput delivers terminal bytes for a stream.
	OnOutput(stream int, data []byte)
	// OnEvent reports "exit" (session id), "revoked" (reason) and "closed"
	// (error text, empty on a clean close).
	OnEvent(kind, detail string)
}

type signer struct {
	s    Signer
	spki []byte
}

func (p *signer) PublicKeySPKI() []byte            { return p.spki }
func (p *signer) SignDER(d []byte) ([]byte, error) { return p.s.SignDER(d) }

func wrap(s Signer) (*signer, error) {
	if s == nil {
		return nil, errors.New("mobile: signer is required")
	}
	spki, err := s.PublicKeySPKI()
	if err != nil {
		return nil, err
	}
	if _, err := attest.ParsePublicKey(spki); err != nil {
		return nil, err
	}
	return &signer{s: s, spki: spki}, nil
}

// Fingerprint returns the SHA-256 fingerprint (hex) of an SPKI.
func Fingerprint(spki []byte) string { return attest.Fingerprint(spki) }

// SignPoP signs a proof of possession for the auth flows:
// purpose "connrelay.auth.v1" (sign-in; set spkiFP) or "connrelay.refresh.v1" (token
// refresh; set deviceID).
func SignPoP(purpose, nonce, spkiFP, deviceID string, s Signer) (string, error) {
	if purpose != attest.PurposeAuth && purpose != attest.PurposeRefresh {
		return "", errors.New("mobile: unsupported purpose")
	}
	w, err := wrap(s)
	if err != nil {
		return "", err
	}
	return attest.SignPoP(w, attest.PoP{Purpose: purpose, Nonce: nonce, SPKIFP: spkiFP, DeviceID: deviceID}, time.Now())
}

// Session is a verified connection to one host.
type Session struct {
	c       *termclient.Client
	path    string
	attempt string
}

type relay struct{ ev Events }

func (r relay) Output(stream uint16, data []byte) {
	if r.ev != nil {
		r.ev.OnOutput(int(stream), data)
	}
}

func (r relay) Event(kind, detail string) {
	if r.ev != nil {
		r.ev.OnEvent(kind, detail)
	}
}

// Connect requests an attempt and establishes a verified transport to the
// host. pinnedFP is the host key fingerprint confirmed at pairing; mode is
// "auto", "webrtc" or "wss". It blocks for up to timeoutMS.
func Connect(api, accessToken, deviceID, hostID, pinnedFP, mode string, timeoutMS int, s Signer, ev Events) (*Session, error) {
	w, err := wrap(s)
	if err != nil {
		return nil, err
	}
	if timeoutMS <= 0 {
		timeoutMS = 30000
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMS)*time.Millisecond)
	defer cancel()
	conn, res, err := client.Connect(ctx, client.Config{API: api, HTTP: &http.Client{Timeout: 30 * time.Second},
		AccessToken: accessToken, DeviceID: deviceID, Signer: w, Mode: mode},
		client.Target{HostID: hostID, PinnedFP: pinnedFP})
	if err != nil {
		return nil, errorCode(err)
	}
	return &Session{c: termclient.New(conn, relay{ev}), path: res.Path, attempt: res.AttemptID}, nil
}

// errorCode turns errors into stable codes the app can map to UI copy.
func errorCode(err error) error {
	var ae *client.APIError
	switch {
	case errors.As(err, &ae):
		return errors.New(ae.Code)
	case errors.Is(err, client.ErrHostKeyMismatch):
		return errors.New("host_key_mismatch")
	}
	var he *termclient.HostError
	if errors.As(err, &he) {
		return errors.New(he.Code)
	}
	return err
}

// Path is "direct", "turn" or "wss_relay".
func (s *Session) Path() string { return s.path }

// AttemptID identifies the connection attempt (diagnostics).
func (s *Session) AttemptID() string { return s.attempt }

func ctx10() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

func asJSON(v any, err error) (string, error) {
	if err != nil {
		return "", errorCode(err)
	}
	b, err := json.Marshal(v)
	return string(b), err
}

// Open starts a new terminal session; returns its JSON description
// {terminal_session_id, stream_id, persistent, resumed, backend}.
func (s *Session) Open(cols, rows int) (string, error) {
	ctx, cancel := ctx10()
	defer cancel()
	return asJSON(s.c.Open(ctx, cols, rows))
}

// Attach re-attaches to a running session.
func (s *Session) Attach(id string, cols, rows int) (string, error) {
	ctx, cancel := ctx10()
	defer cancel()
	return asJSON(s.c.Attach(ctx, id, cols, rows))
}

// List returns the host's sessions as JSON.
func (s *Session) List() (string, error) {
	ctx, cancel := ctx10()
	defer cancel()
	return asJSON(s.c.List(ctx))
}

// Input sends keystrokes or pasted text to a stream.
func (s *Session) Input(stream int, data []byte) error {
	ctx, cancel := ctx10()
	defer cancel()
	return errorCode(s.c.Input(ctx, uint16(stream), data))
}

// Resize reports a new terminal size for a stream.
func (s *Session) Resize(stream, cols, rows int) error { return s.c.Resize(uint16(stream), cols, rows) }

// Detach leaves the session running on the host.
func (s *Session) Detach(stream int) error { return s.c.Detach(uint16(stream)) }

// Terminate ends a session's processes (explicit user action).
func (s *Session) Terminate(id string) error {
	ctx, cancel := ctx10()
	defer cancel()
	return errorCode(s.c.Terminate(ctx, id))
}

// Close ends the connection; sessions keep running on the host.
func (s *Session) Close() { _ = s.c.Close() }
