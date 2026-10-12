// Package lease holds the host's view of which phones may connect: a signed
// grant lease from the control plane, verified against pinned keys. When the
// lease expires (control plane unreachable) new sessions are refused.
package lease

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/rohansen856/connrelay/agents/host/internal/agentcfg"
	"github.com/rohansen856/connrelay/core/connrelaycore/attest"
	"github.com/rohansen856/connrelay/core/connrelaycore/token"
)

// Errors.
var (
	ErrNoLease  = errors.New("lease_expired")
	ErrNotGrant = errors.New("access_grant_missing")
)

// KeySet converts pinned JWKs into a token key set.
func KeySet(jwks []agentcfg.JWK) (token.KeySet, error) {
	ks := token.KeySet{}
	for _, k := range jwks {
		if k.KTY != "OKP" || k.CRV != "Ed25519" {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("lease: bad pinned key %s", k.KID)
		}
		ks[k.KID] = ed25519.PublicKey(x)
	}
	if len(ks) == 0 {
		return nil, errors.New("lease: no usable pinned keys")
	}
	return ks, nil
}

// Phone is one allowed phone.
type Phone struct {
	DeviceID string
	Key      *ecdsa.PublicKey
	SPKI     []byte
	Caps     []string
	Expires  time.Time // zero = no grant expiry
}

// Cache is the current lease.
type Cache struct {
	host string
	keys token.KeySet
	now  func() time.Time

	mu      sync.RWMutex
	phones  map[string]Phone
	expires time.Time
}

// New returns an empty cache for host, trusting keys.
func New(host string, keys token.KeySet, now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	return &Cache{host: host, keys: keys, now: now, phones: map[string]Phone{}}
}

// Apply verifies and installs a lease. It returns the phones that were
// allowed before and are not any more (their peers must be closed).
func (c *Cache) Apply(jws string) ([]string, error) {
	var l token.Lease
	if err := c.keys.Verify(jws, token.TypeLease, c.now(), &l); err != nil {
		return nil, err
	}
	if l.Host != c.host {
		return nil, errors.New("lease: issued for another host")
	}
	next := map[string]Phone{}
	for _, g := range l.Grants {
		spki, err := base64.RawURLEncoding.DecodeString(g.PhoneKeySPKI)
		if err != nil {
			return nil, err
		}
		pub, err := attest.ParsePublicKey(spki)
		if err != nil {
			return nil, err
		}
		p := Phone{DeviceID: g.PhoneDeviceID, Key: pub, SPKI: spki, Caps: g.Caps}
		if g.GrantExpiresAt != 0 {
			p.Expires = time.Unix(g.GrantExpiresAt, 0)
		}
		next[g.PhoneDeviceID] = p
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var dropped []string
	for id := range c.phones {
		if _, ok := next[id]; !ok {
			dropped = append(dropped, id)
		}
	}
	c.phones, c.expires = next, time.Unix(l.EXP, 0)
	return dropped, nil
}

// Valid reports whether the lease is current.
func (c *Cache) Valid() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now().Before(c.expires)
}

// Lookup returns the phone if the lease is current and grants cap.
func (c *Cache) Lookup(phone, cap string) (Phone, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.now().Before(c.expires) {
		return Phone{}, ErrNoLease
	}
	p, ok := c.phones[phone]
	if !ok || !slices.Contains(p.Caps, cap) || (!p.Expires.IsZero() && !c.now().Before(p.Expires)) {
		return Phone{}, ErrNotGrant
	}
	return p, nil
}

// Remove drops a phone immediately (revoke_notice), before the next lease.
func (c *Cache) Remove(phone string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.phones, phone)
}
