// Package turncred issues short-lived TURN credentials using the TURN REST
// scheme that coturn implements with use-auth-secret:
//
//	username   = "<unix expiry>:<attempt id>"
//	credential = base64(HMAC-SHA1(shared secret, username))
package turncred

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"strconv"
	"time"
)

// DefaultTTL is the credential lifetime.
const DefaultTTL = 600 * time.Second

// Credential is one TURN username/password pair.
type Credential struct {
	Username   string    `json:"username"`
	Credential string    `json:"credential"`
	Expires    time.Time `json:"credential_expires_at"`
}

// Issue derives a credential for attemptID valid until now+ttl.
func Issue(secret []byte, attemptID string, now time.Time, ttl time.Duration) Credential {
	exp := now.Add(ttl).Truncate(time.Second)
	user := strconv.FormatInt(exp.Unix(), 10) + ":" + attemptID
	m := hmac.New(sha1.New, secret)
	m.Write([]byte(user))
	return Credential{Username: user, Credential: base64.StdEncoding.EncodeToString(m.Sum(nil)), Expires: exp}
}
