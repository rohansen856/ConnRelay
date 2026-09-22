// Package httpx holds the HTTP conventions shared by all handlers: request
// IDs, the JSON error envelope, strict body decoding with size limits.
package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type ctxKey int

const requestIDKey ctxKey = 0

// RequestID returns the request ID stored by WithRequestID.
func RequestID(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

// WithRequestID assigns every request an ID, echoed in X-Request-Id. Client
// supplied IDs are ignored so they cannot be used to forge correlation.
func WithRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b [12]byte
		_, _ = rand.Read(b[:])
		id := "req_" + hex.EncodeToString(b[:])
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

// Error is an API error with a stable code.
type Error struct {
	Status    int            `json:"-"`
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details,omitempty"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// E builds an Error.
func E(status int, code, msg string) *Error { return &Error{Status: status, Code: code, Message: msg} }

// Common errors.
var (
	ErrUnauthenticated = E(http.StatusUnauthorized, "unauthenticated", "Sign in again.")
	ErrNotFound        = E(http.StatusNotFound, "not_found", "Not found.")
	ErrInternal        = &Error{Status: http.StatusInternalServerError, Code: "internal_error", Message: "Something went wrong.", Retryable: true}
)

// WriteError writes the error envelope. Unknown errors become internal_error
// without leaking their text.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	var e *Error
	if !errors.As(err, &e) {
		e = ErrInternal
	}
	body := map[string]any{"error": map[string]any{
		"code": e.Code, "message": e.Message, "retryable": e.Retryable,
		"request_id": RequestID(r.Context()), "details": orEmpty(e.Details),
	}}
	WriteJSON(w, e.Status, body)
}

func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// WriteJSON writes v with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Decode reads a JSON body of at most limit bytes into v, rejecting unknown
// fields and trailing data.
func Decode(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		return E(http.StatusUnsupportedMediaType, "validation_failed", "Expected application/json.")
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return E(http.StatusRequestEntityTooLarge, "validation_failed", "Request body too large.")
		}
		return &Error{Status: http.StatusBadRequest, Code: "validation_failed", Message: "Malformed request.",
			Details: map[string]any{"reason": shortReason(err)}}
	}
	if _, err := dec.Token(); err != io.EOF {
		return E(http.StatusBadRequest, "validation_failed", "Unexpected data after JSON body.")
	}
	return nil
}

// shortReason keeps decoder errors useful without echoing request content.
func shortReason(err error) string {
	var ute *json.UnmarshalTypeError
	if errors.As(err, &ute) {
		return fmt.Sprintf("field %q has the wrong type", ute.Field)
	}
	if strings.HasPrefix(err.Error(), "json: unknown field") {
		return err.Error()
	}
	return "invalid JSON"
}

// Handler adapts a function returning an error to http.Handler.
type Handler func(w http.ResponseWriter, r *http.Request) error

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h(w, r); err != nil {
		WriteError(w, r, err)
	}
}
