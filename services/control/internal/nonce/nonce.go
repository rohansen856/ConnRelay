// Package nonce issues single-use, short-lived server nonces (proof-of-
// possession challenges). Only hashes are kept, in memory: a restart simply
// invalidates outstanding nonces and clients ask again.
package nonce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

// Store holds outstanding nonces.
type Store struct {
	ttl  time.Duration
	max  int
	now  func() time.Time
	mu   sync.Mutex
	live map[[32]byte]time.Time
}

// New returns a store whose nonces expire after ttl. max bounds memory; when
// full, issuing evicts expired entries first and then refuses.
func New(ttl time.Duration, max int) *Store {
	return &Store{ttl: ttl, max: max, now: time.Now, live: map[[32]byte]time.Time{}}
}

// Issue returns a base64url nonce and its expiry, or ok=false when full.
func (s *Store) Issue() (string, time.Time, bool) {
	var b [32]byte
	_, _ = rand.Read(b[:])
	n := base64.RawURLEncoding.EncodeToString(b[:])
	exp := s.now().Add(s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.live) >= s.max {
		s.sweep()
		if len(s.live) >= s.max {
			return "", time.Time{}, false
		}
	}
	s.live[sha256.Sum256([]byte(n))] = exp
	return n, exp, true
}

// Consume reports whether n was issued, is unexpired and unused, and marks
// it used.
func (s *Store) Consume(n string) bool {
	h := sha256.Sum256([]byte(n))
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.live[h]
	if !ok {
		return false
	}
	delete(s.live, h)
	return s.now().Before(exp)
}

func (s *Store) sweep() {
	now := s.now()
	for k, exp := range s.live {
		if !now.Before(exp) {
			delete(s.live, k)
		}
	}
}
