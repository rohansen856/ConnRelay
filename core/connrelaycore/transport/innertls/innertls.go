// Package innertls runs TLS 1.3 end to end between two peers inside the WSS
// relay. Certificates are ephemeral and self-signed; instead of chain
// validation, each side pins the fingerprint the peer announced over
// signaling. Identity attestation later binds the certificate to the peer's
// enrolled device key.
package innertls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/rohansen856/connrelay/core/connrelaycore/attest"
)

// ALPN is the application protocol negotiated on the inner TLS connection.
const ALPN = "connrelay/1"

// ErrFingerprint is returned when the peer certificate does not match the
// pinned fingerprint.
var ErrFingerprint = errors.New("innertls: peer certificate fingerprint mismatch")

// Identity is an ephemeral certificate and key for one connection attempt.
type Identity struct {
	Cert        tls.Certificate
	Fingerprint string // SHA-256 of the DER certificate, hex
}

// NewIdentity generates a P-256 key and a self-signed certificate valid for
// one hour.
func NewIdentity(attemptID string) (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "connrelay-" + attemptID},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Cert:        tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		Fingerprint: attest.Fingerprint(der),
	}, nil
}

func pin(expected string) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) != 1 {
			return fmt.Errorf("%w: expected exactly one certificate", ErrFingerprint)
		}
		if attest.Fingerprint(raw[0]) != expected {
			return ErrFingerprint
		}
		return nil
	}
}

func config(id *Identity, peerFP string) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{id.Cert},
		NextProtos:            []string{ALPN},
		InsecureSkipVerify:    true, // chain validation replaced by fingerprint pinning
		VerifyPeerCertificate: pin(peerFP),
		ClientAuth:            tls.RequireAnyClientCert,
	}
}

// Server performs the host side of the handshake.
func Server(ctx context.Context, c net.Conn, id *Identity, peerFP string) (*tls.Conn, error) {
	tc := tls.Server(c, config(id, peerFP))
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tc, checkALPN(tc)
}

// Client performs the phone side of the handshake.
func Client(ctx context.Context, c net.Conn, id *Identity, peerFP string) (*tls.Conn, error) {
	cfg := config(id, peerFP)
	cfg.ServerName = "connrelay.invalid"
	tc := tls.Client(c, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tc, checkALPN(tc)
}

func checkALPN(tc *tls.Conn) error {
	st := tc.ConnectionState()
	if st.NegotiatedProtocol != ALPN || st.Version != tls.VersionTLS13 {
		tc.Close()
		return fmt.Errorf("innertls: unexpected ALPN %q / version %x", st.NegotiatedProtocol, st.Version)
	}
	return nil
}
