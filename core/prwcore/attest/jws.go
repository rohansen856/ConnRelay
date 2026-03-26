// Package attest implements device-key signatures (ES256 compact JWS over
// JCS-canonical JSON) and the peer identity attestation (protocol v1 §10).
//
// No cryptography is implemented here: signing and verification use
// crypto/ecdsa, and canonicalisation uses an RFC 8785 library.
package attest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/gowebpki/jcs"
)

var b64 = base64.RawURLEncoding

// ErrInvalid is returned (wrapped) for any signature or claim failure.
var ErrInvalid = errors.New("attest: invalid")

// Signer abstracts a P-256 device key. Hardware-backed keys (Android
// Keystore, iOS Secure Enclave) implement it without exposing the key.
type Signer interface {
	// PublicKeySPKI returns the DER SubjectPublicKeyInfo of the key.
	PublicKeySPKI() []byte
	// SignDER signs a SHA-256 digest and returns an ASN.1 DER ECDSA signature.
	SignDER(digest []byte) ([]byte, error)
}

// SoftwareSigner is a Signer backed by an in-memory key (host agent, tests).
type SoftwareSigner struct{ Key *ecdsa.PrivateKey }

// NewSoftwareSigner generates a fresh P-256 key.
func NewSoftwareSigner() (*SoftwareSigner, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &SoftwareSigner{Key: k}, nil
}

func (s *SoftwareSigner) PublicKeySPKI() []byte {
	b, err := x509.MarshalPKIXPublicKey(&s.Key.PublicKey)
	if err != nil {
		panic(err) // cannot fail for a valid P-256 key
	}
	return b
}

func (s *SoftwareSigner) SignDER(digest []byte) ([]byte, error) {
	return s.Key.Sign(rand.Reader, digest, crypto.SHA256)
}

// Fingerprint returns the lowercase hex SHA-256 of DER bytes (an SPKI or a
// certificate).
func Fingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// DERToRaw converts an ASN.1 DER ECDSA P-256 signature into the 64-byte r||s
// form required by JWS ES256.
func DERToRaw(der []byte) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil {
		return nil, fmt.Errorf("%w: bad DER signature", ErrInvalid)
	}
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.BitLen() > 256 || sig.S.BitLen() > 256 {
		return nil, fmt.Errorf("%w: signature out of range", ErrInvalid)
	}
	out := make([]byte, 64)
	sig.R.FillBytes(out[:32])
	sig.S.FillBytes(out[32:])
	return out, nil
}

// ParsePublicKey parses a DER SPKI into a P-256 public key.
func ParsePublicKey(spki []byte) (*ecdsa.PublicKey, error) {
	pk, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	ec, ok := pk.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: not a P-256 key", ErrInvalid)
	}
	return ec, nil
}

const es256Header = `{"alg":"ES256","typ":"JWT"}`

// Sign canonicalises claims with JCS and returns a compact ES256 JWS.
func Sign(s Signer, claims any) (string, error) {
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload, err := jcs.Transform(raw)
	if err != nil {
		return "", err
	}
	signingInput := b64.EncodeToString([]byte(es256Header)) + "." + b64.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	der, err := s.SignDER(digest[:])
	if err != nil {
		return "", err
	}
	sig, err := DERToRaw(der)
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64.EncodeToString(sig), nil
}

// Verify checks a compact ES256 JWS against pub and returns the raw payload.
func Verify(pub *ecdsa.PublicKey, jws string) ([]byte, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: malformed JWS", ErrInvalid)
	}
	hdr, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header encoding", ErrInvalid)
	}
	var h struct {
		Alg  string `json:"alg"`
		Crit any    `json:"crit"`
	}
	if err := json.Unmarshal(hdr, &h); err != nil || h.Alg != "ES256" || h.Crit != nil {
		return nil, fmt.Errorf("%w: unsupported header", ErrInvalid)
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload encoding", ErrInvalid)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, fmt.Errorf("%w: signature encoding", ErrInvalid)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, fmt.Errorf("%w: bad signature", ErrInvalid)
	}
	return payload, nil
}
