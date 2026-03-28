package turncred

import (
	"testing"
	"time"
)

func TestVector(t *testing.T) {
	// Fixed vector: HMAC-SHA1("TEST-ONLY-secret", "1760314440:att-1").
	c := Issue([]byte("TEST-ONLY-secret"), "att-1", time.Unix(1760313840, 0), DefaultTTL)
	if c.Username != "1760314440:att-1" {
		t.Fatalf("username %q", c.Username)
	}
	if c.Credential != "G+UacPrqN/v+sWeBxcvJ771CllM=" {
		t.Fatalf("credential %q", c.Credential)
	}
}
