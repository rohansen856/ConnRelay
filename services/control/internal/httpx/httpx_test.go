package httpx

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func decode(body string, limit int64) error {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	var v struct {
		Name string `json:"name"`
	}
	return Decode(httptest.NewRecorder(), r, limit, &v)
}

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestDecode(t *testing.T) {
	if err := decode(`{"name":"ok"}`, 100); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"unknown field": `{"name":"x","admin":true}`,
		"trailing":      `{"name":"x"}{"name":"y"}`,
		"wrong type":    `{"name":1}`,
		"not json":      `name=x`,
	} {
		if code(decode(body, 100)) != "validation_failed" {
			t.Errorf("%s accepted", name)
		}
	}
	err := decode(`{"name":"`+strings.Repeat("x", 200)+`"}`, 50)
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %v", err)
	}
}

func TestErrorEnvelopeHidesInternalErrors(t *testing.T) {
	h := WithRequestID(Handler(func(http.ResponseWriter, *http.Request) error {
		return errors.New("pq: password authentication failed for user prw")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "password") {
		t.Fatalf("leaked internal error: %d %s", rec.Code, rec.Body)
	}
	var body struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Error.Code != "internal_error" || body.Error.RequestID == "" || body.Error.RequestID != rec.Header().Get("X-Request-Id") {
		t.Fatalf("envelope %s", rec.Body)
	}
}
