package nonce

import (
	"testing"
	"time"
)

func TestSingleUse(t *testing.T) {
	s := New(time.Minute, 10)
	n, _, ok := s.Issue()
	if !ok || !s.Consume(n) {
		t.Fatal("fresh nonce rejected")
	}
	if s.Consume(n) {
		t.Fatal("nonce accepted twice")
	}
	if s.Consume("never-issued") {
		t.Fatal("unknown nonce accepted")
	}
}

func TestExpiry(t *testing.T) {
	s := New(time.Minute, 10)
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }
	n, _, _ := s.Issue()
	now = now.Add(2 * time.Minute)
	if s.Consume(n) {
		t.Fatal("expired nonce accepted")
	}
}

func TestBounded(t *testing.T) {
	s := New(time.Minute, 2)
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }
	s.Issue()
	s.Issue()
	if _, _, ok := s.Issue(); ok {
		t.Fatal("store grew past its bound")
	}
	now = now.Add(2 * time.Minute) // all expired: sweeping makes room
	if _, _, ok := s.Issue(); !ok {
		t.Fatal("expired entries not swept")
	}
}
