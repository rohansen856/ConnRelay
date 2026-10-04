package pairing

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// crockford is the Crockford base32 alphabet (no I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewCode returns an 8-character code (40 random bits) as "XXXX-XXXX".
func NewCode() string {
	var b [5]byte
	_, _ = rand.Read(b[:])
	v := uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4])
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = crockford[v&31]
		v >>= 5
	}
	return string(out[:4]) + "-" + string(out[4:])
}

// NormalizeCode upper-cases, strips separators and maps look-alike
// characters (I, L -> 1; O -> 0). It returns "" if the result is not a valid
// 8-character code.
func NormalizeCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch r {
		case '-', ' ':
			continue
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		}
		if !strings.ContainsRune(crockford, r) {
			return ""
		}
		b.WriteRune(r)
	}
	if b.Len() != 8 {
		return ""
	}
	return b.String()
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// random returns n random bytes, base64url-encoded.
func random(n int) string { return base64.RawURLEncoding.EncodeToString(randBytes(n)) }

// mac computes the stored form of a secret under the server pepper.
func mac(pepper []byte, label, v string) []byte {
	m := hmac.New(sha256.New, pepper)
	m.Write([]byte(label + ":" + v))
	return m.Sum(nil)
}
