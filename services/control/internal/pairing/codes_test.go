package pairing

import "testing"

func TestCodes(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		c := NewCode()
		if len(c) != 9 || c[4] != '-' {
			t.Fatalf("format %q", c)
		}
		n := NormalizeCode(c)
		if n == "" || len(n) != 8 {
			t.Fatalf("normalize %q", c)
		}
		seen[n] = true
	}
	if len(seen) < 990 {
		t.Fatalf("too many collisions: %d unique of 1000", len(seen))
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"7kq2-m9xt": "7KQ2M9XT",
		"7KQ2 M9XT": "7KQ2M9XT",
		"OILo-1234": "0110" + "1234",
		"7KQ2M9X":   "", // too short
		"7KQ2-M9XU": "", // U is not in the alphabet
		"7KQ2-M9X!": "",
	} {
		if got := NormalizeCode(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}
