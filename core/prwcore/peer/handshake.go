// Package peer runs the data-plane handshake on a fresh transport: version
// negotiation (hello), mutual identity attestation (peer.attest) and the
// peer.identity_verified gate (protocol v1 §10–11). No terminal message may
// be exchanged before Handshake returns successfully.
package peer

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/rohansen856/connrelay/core/prwcore/attest"
	"github.com/rohansen856/connrelay/core/prwcore/control"
	"github.com/rohansen856/connrelay/core/prwcore/transport"
)

// ProtocolVersion is the data-plane protocol version implemented here.
const ProtocolVersion = 1

// Timeout bounds the whole handshake.
const Timeout = 5 * time.Second

// Roles.
const (
	RolePhone = "phone"
	RoleHost  = "host"
)

// ErrIdentity is returned for any attestation failure (peer_identity_mismatch).
var ErrIdentity = errors.New("peer_identity_mismatch")

// ErrVersion is returned when no common protocol version exists.
var ErrVersion = errors.New("unsupported_version")

// Params configure one side of the handshake.
type Params struct {
	Role    string // RolePhone or RoleHost
	Self    string // own device ID
	Peer    string // expected peer device ID
	Attempt string
	Nonce   string // attestation nonce from the ticket
	Cap     string // requested capability ("terminal")
	Signer  attest.Signer
	PeerKey *ecdsa.PublicKey // pinned peer identity key
	// Ticket is sent by the phone alongside its attestation.
	Ticket string
	// CheckTicket is called by the host with the phone's ticket; it must
	// verify signature, audience, expiry, single use and grant, and return the
	// allowed capabilities.
	CheckTicket func(ticket string) (caps []string, err error)
	Impl        string
	Now         func() time.Time
}

// Result describes a verified peer.
type Result struct {
	PV     int
	Claims *attest.Claims
	Ticket string // the phone's ticket, as received by the host
}

// Handshake runs the handshake. The caller owns conn and must close it on error.
func Handshake(ctx context.Context, conn transport.Conn, p Params) (*Result, error) {
	if p.Now == nil {
		p.Now = time.Now
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	type recvd struct {
		env *control.Envelope
		err error
	}
	in := make(chan recvd, 4)
	go func() {
		for i := 0; i < 3; i++ {
			f, err := conn.Recv()
			if err != nil {
				in <- recvd{err: err}
				return
			}
			env, err := control.Decode(f)
			in <- recvd{env, err}
			if err != nil {
				return
			}
		}
	}()
	next := func(want string) (*control.Envelope, error) {
		select {
		case r := <-in:
			if r.err != nil {
				return nil, r.err
			}
			if r.env.Type != want {
				return nil, fmt.Errorf("%w: expected %s, got %s", ErrIdentity, want, r.env.Type)
			}
			return r.env, nil
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: timeout waiting for %s", ErrIdentity, want)
		}
	}
	send := func(typ string, payload any) error {
		env, err := control.New(typ, payload)
		if err != nil {
			return err
		}
		f, err := env.Frame()
		if err != nil {
			return err
		}
		return conn.Send(f)
	}

	// 1. hello
	if err := send(control.TypeHello, control.Hello{PVMin: ProtocolVersion, PVMax: ProtocolVersion, Impl: p.Impl}); err != nil {
		return nil, err
	}
	env, err := next(control.TypeHello)
	if err != nil {
		return nil, err
	}
	var h control.Hello
	if err := env.Unmarshal(&h); err != nil {
		return nil, err
	}
	pv := min(h.PVMax, ProtocolVersion)
	if pv < h.PVMin || pv < ProtocolVersion {
		return nil, ErrVersion
	}

	// 2. attestation
	peerRole := RoleHost
	if p.Role == RoleHost {
		peerRole = RolePhone
	}
	now := p.Now()
	jws, err := attest.Sign(p.Signer, attest.NewClaims(now, attest.Claims{
		Attempt: p.Attempt, From: p.Self, To: p.Peer, Role: p.Role, Nonce: p.Nonce,
		Transport: conn.Transport(), LocalFP: conn.LocalCertFP(), RemoteFP: conn.RemoteCertFP(), Cap: p.Cap,
	}))
	if err != nil {
		return nil, err
	}
	pa := control.PeerAttest{JWS: jws}
	if p.Role == RolePhone {
		pa.Ticket = p.Ticket
	}
	if err := send(control.TypePeerAttest, pa); err != nil {
		return nil, err
	}
	env, err = next(control.TypePeerAttest)
	if err != nil {
		return nil, err
	}
	var got control.PeerAttest
	if err := env.Unmarshal(&got); err != nil {
		return nil, err
	}
	caps := []string{p.Cap}
	if p.Role == RoleHost {
		if p.CheckTicket == nil {
			return nil, fmt.Errorf("%w: host has no ticket verifier", ErrIdentity)
		}
		if caps, err = p.CheckTicket(got.Ticket); err != nil {
			return nil, fmt.Errorf("%w: ticket: %v", ErrIdentity, err)
		}
	}
	claims, err := attest.VerifyPeer(got.JWS, attest.Expect{
		PeerKey: p.PeerKey, Attempt: p.Attempt, Nonce: p.Nonce, Self: p.Self, Peer: p.Peer,
		PeerRole: peerRole, Transport: conn.Transport(),
		ObservedPeer: conn.RemoteCertFP(), OwnCert: conn.LocalCertFP(),
		AllowedCaps: caps, Now: p.Now(),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdentity, err)
	}

	// 3. both sides confirm
	if err := send(control.TypeIdentityVerified, struct{}{}); err != nil {
		return nil, err
	}
	if _, err := next(control.TypeIdentityVerified); err != nil {
		return nil, err
	}
	return &Result{PV: pv, Claims: claims, Ticket: got.Ticket}, nil
}
