// Package pairclient runs the host side of pairing (API §5): create a
// challenge signed with the host key, show it, wait for the phone's approval
// and prove possession of the key over the server's second nonce.
package pairclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/rohansen856/connrelay/agents/host/internal/agentcfg"
	"github.com/rohansen856/connrelay/core/prwcore/attest"
)

// Challenge is what the user needs to approve pairing on the phone.
type Challenge struct {
	ID          string `json:"challenge_id"`
	Ref         string `json:"pairing_ref"`
	Code        string `json:"display_code"`
	ExpiresAt   string `json:"expires_at"`
	WaitToken   string `json:"wait_token"`
	QRPayload   string `json:"qr_payload"`
	Fingerprint string `json:"-"`
}

// Client talks to the control plane.
type Client struct {
	Server  string
	HTTP    *http.Client
	Key     *attest.SoftwareSigner
	Version string
}

func (c *Client) do(ctx context.Context, method, path, bearer string, body any, out any) (int, error) {
	var r *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	} else {
		r = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Server+path, r)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return resp.StatusCode, &APIError{Status: resp.StatusCode, Code: e.Error.Code, Message: e.Error.Message}
	}
	if out != nil {
		return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, nil
}

// APIError is an error response from the control plane.
type APIError struct {
	Status        int
	Code, Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("%s (%s)", e.Message, e.Code) }

func osRelease() (id, version string) {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return runtime.GOOS, ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		}
	}
	return id, version
}

// Create starts pairing for hostname.
func (c *Client) Create(ctx context.Context, hostname string) (*Challenge, error) {
	spki := c.Key.PublicKeySPKI()
	fp := attest.Fingerprint(spki)
	sig, err := attest.SignPoP(c.Key, attest.PoP{Purpose: attest.PurposePairCreate, SPKIFP: fp}, time.Now())
	if err != nil {
		return nil, err
	}
	id, ver := osRelease()
	var ch Challenge
	_, err = c.do(ctx, "POST", "/v1/pairing/challenges", "", map[string]any{
		"host_public_key_spki": base64.RawURLEncoding.EncodeToString(spki), "hostname": hostname,
		"os": map[string]string{"id": id, "version": ver}, "agent_version": c.Version,
		"proto": map[string]int{"min": 1, "max": 1}, "pop_sig": sig}, &ch)
	ch.Fingerprint = fp
	return &ch, err
}

// Wait long-polls until the phone approves and returns nonce2.
func (c *Client) Wait(ctx context.Context, ch *Challenge) (string, error) {
	for {
		var r struct {
			Status string `json:"status"`
			Nonce2 string `json:"nonce2"`
		}
		_, err := c.do(ctx, "GET", "/v1/pairing/challenges/"+ch.ID+"/wait", ch.WaitToken, nil, &r)
		if err != nil {
			return "", err
		}
		if r.Status == "approved" {
			return r.Nonce2, nil
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
	}
}

// Complete proves key possession and returns the enrolment state.
func (c *Client) Complete(ctx context.Context, ch *Challenge, nonce2 string) (*agentcfg.State, error) {
	sig, err := attest.SignPoP(c.Key, attest.PoP{Purpose: attest.PurposePairComplete, ChallengeID: ch.ID, Nonce: nonce2,
		SPKIFP: ch.Fingerprint}, time.Now())
	if err != nil {
		return nil, err
	}
	var r struct {
		DeviceID  string `json:"device_id"`
		AccountID string `json:"account_id"`
		ControlWS string `json:"control_ws_url"`
		JWKS      struct {
			Keys []agentcfg.JWK `json:"keys"`
		} `json:"jwks"`
	}
	if _, err := c.do(ctx, "POST", "/v1/pairing/challenges/"+ch.ID+"/complete", ch.WaitToken, map[string]string{"sig": sig}, &r); err != nil {
		return nil, err
	}
	if r.DeviceID == "" || len(r.JWKS.Keys) == 0 || r.ControlWS == "" {
		return nil, errors.New("incomplete pairing response")
	}
	return &agentcfg.State{Server: c.Server, ControlWS: r.ControlWS, DeviceID: r.DeviceID, AccountID: r.AccountID, JWKS: r.JWKS.Keys}, nil
}
