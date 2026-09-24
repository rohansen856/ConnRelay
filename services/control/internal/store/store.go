// Package store holds the control plane's PostgreSQL queries. Every query
// that reads account-owned data takes the account ID derived from the
// authenticated caller, never from request input.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a row does not exist (or belongs to another
// account, which callers must treat identically).
var ErrNotFound = errors.New("store: not found")

// Store wraps the pool.
type Store struct{ Pool *pgxpool.Pool }

// Q is satisfied by the pool and by transactions.
type Q interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// InTx runs f in a transaction, committing on nil error.
func (s *Store) InTx(ctx context.Context, f func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.Pool, f)
}

// NewID returns a time-ordered UUIDv7.
func NewID() uuid.UUID { return uuid.Must(uuid.NewV7()) }

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// IsUniqueViolation reports a unique-constraint failure.
func IsUniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// ---- accounts ----

// Account is an account row.
type Account struct {
	ID          uuid.UUID
	Email       *string
	DisplayName *string
	Status      string
}

// UpsertGoogleAccount creates or refreshes the account for a Google subject.
func UpsertGoogleAccount(ctx context.Context, q Q, subject string, email, name *string) (Account, error) {
	var a Account
	err := q.QueryRow(ctx, `
		INSERT INTO accounts (id, identity_provider, identity_subject, email, display_name)
		VALUES ($1, 'google', $2, $3, $4)
		ON CONFLICT (identity_provider, identity_subject)
		DO UPDATE SET email = COALESCE(EXCLUDED.email, accounts.email),
		              display_name = COALESCE(EXCLUDED.display_name, accounts.display_name)
		RETURNING id, email, display_name, status`, NewID(), subject, email, name).
		Scan(&a.ID, &a.Email, &a.DisplayName, &a.Status)
	return a, err
}

// GetAccount loads an account by ID.
func GetAccount(ctx context.Context, q Q, id uuid.UUID) (Account, error) {
	var a Account
	err := q.QueryRow(ctx, `SELECT id, email, display_name, status FROM accounts WHERE id = $1`, id).
		Scan(&a.ID, &a.Email, &a.DisplayName, &a.Status)
	return a, notFound(err)
}

// ---- devices ----

// Device is a device row.
type Device struct {
	ID              uuid.UUID
	AccountID       uuid.UUID
	Kind            string
	Platform        string
	DisplayName     string
	PublicKey       []byte
	KeyFingerprint  string
	SoftwareVersion *string
	AdminState      string
	LastSeenAt      *time.Time
	EnrolledAt      time.Time
	RevokedAt       *time.Time
	Version         int
}

const deviceCols = `id, account_id, kind, platform, display_name, public_key, key_fingerprint,
	software_version, admin_state, last_seen_at, enrolled_at, revoked_at, version`

func scanDevice(r pgx.Row) (Device, error) {
	var d Device
	err := r.Scan(&d.ID, &d.AccountID, &d.Kind, &d.Platform, &d.DisplayName, &d.PublicKey, &d.KeyFingerprint,
		&d.SoftwareVersion, &d.AdminState, &d.LastSeenAt, &d.EnrolledAt, &d.RevokedAt, &d.Version)
	return d, notFound(err)
}

// GetDevice loads a device of the account.
func GetDevice(ctx context.Context, q Q, accountID, id uuid.UUID) (Device, error) {
	return scanDevice(q.QueryRow(ctx, `SELECT `+deviceCols+` FROM devices WHERE account_id = $1 AND id = $2`, accountID, id))
}

// GetDeviceByID loads a device without account scope (agent login, where the
// device key itself authenticates).
func GetDeviceByID(ctx context.Context, q Q, id uuid.UUID) (Device, error) {
	return scanDevice(q.QueryRow(ctx, `SELECT `+deviceCols+` FROM devices WHERE id = $1`, id))
}

// FindLiveDeviceByFingerprint finds a non-revoked device with this key.
func FindLiveDeviceByFingerprint(ctx context.Context, q Q, accountID uuid.UUID, fp string) (Device, error) {
	return scanDevice(q.QueryRow(ctx, `SELECT `+deviceCols+` FROM devices
		WHERE account_id = $1 AND key_fingerprint = $2 AND admin_state <> 'revoked'`, accountID, fp))
}

// NewDevice describes a device to insert.
type NewDevice struct {
	AccountID       uuid.UUID
	Kind, Platform  string
	DisplayName     string
	PublicKey       []byte
	KeyFingerprint  string
	SoftwareVersion string
}

// InsertDevice inserts an active device and its credential history row.
func InsertDevice(ctx context.Context, q Q, n NewDevice) (Device, error) {
	id := NewID()
	d, err := scanDevice(q.QueryRow(ctx, `
		INSERT INTO devices (id, account_id, kind, platform, display_name, public_key, key_fingerprint, software_version)
		VALUES ($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''))
		RETURNING `+deviceCols, id, n.AccountID, n.Kind, n.Platform, n.DisplayName, n.PublicKey, n.KeyFingerprint, n.SoftwareVersion))
	if err != nil {
		return d, err
	}
	_, err = q.Exec(ctx, `INSERT INTO device_credentials (id, account_id, device_id, key_purpose, alg, public_key, key_fingerprint)
		VALUES ($1,$2,$3,'identity_signing','ecdsa-p256',$4,$5)`, NewID(), n.AccountID, id, n.PublicKey, n.KeyFingerprint)
	return d, err
}

// TouchDevice records the software version and last-seen time.
func TouchDevice(ctx context.Context, q Q, id uuid.UUID, version string) error {
	_, err := q.Exec(ctx, `UPDATE devices SET last_seen_at = now(),
		software_version = COALESCE(NULLIF($2,''), software_version) WHERE id = $1`, id, version)
	return err
}

// ---- auth sessions ----

// AuthSession is a refresh-token session of one phone.
type AuthSession struct {
	ID            uuid.UUID
	AccountID     uuid.UUID
	DeviceID      uuid.UUID
	FamilyID      uuid.UUID
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	RevokeReason  *string
	FamilyStarted time.Time
}

// InsertAuthSession stores a new session holding refreshHash.
func InsertAuthSession(ctx context.Context, q Q, accountID, deviceID, familyID uuid.UUID, rotatedFrom *uuid.UUID,
	refreshHash []byte, expires time.Time, ua string) (uuid.UUID, error) {
	id := NewID()
	_, err := q.Exec(ctx, `INSERT INTO auth_sessions (id, account_id, device_id, token_family_id, refresh_token_hash,
		rotated_from_id, expires_at, user_agent_summary) VALUES ($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''))`,
		id, accountID, deviceID, familyID, refreshHash, rotatedFrom, expires, truncate(ua, 255))
	return id, err
}

// LockAuthSessionByHash loads and row-locks the session for a refresh token.
func LockAuthSessionByHash(ctx context.Context, q Q, hash []byte) (AuthSession, error) {
	var s AuthSession
	err := q.QueryRow(ctx, `
		SELECT s.id, s.account_id, s.device_id, s.token_family_id, s.expires_at, s.revoked_at, s.revoke_reason,
		       (SELECT min(created_at) FROM auth_sessions f WHERE f.token_family_id = s.token_family_id)
		FROM auth_sessions s WHERE s.refresh_token_hash = $1 FOR UPDATE`, hash).
		Scan(&s.ID, &s.AccountID, &s.DeviceID, &s.FamilyID, &s.ExpiresAt, &s.RevokedAt, &s.RevokeReason, &s.FamilyStarted)
	return s, notFound(err)
}

// GetLiveAuthSession returns a session if it is neither revoked nor expired.
func GetLiveAuthSession(ctx context.Context, q Q, id uuid.UUID) (AuthSession, error) {
	var s AuthSession
	err := q.QueryRow(ctx, `SELECT id, account_id, device_id, token_family_id, expires_at, revoked_at, revoke_reason, created_at
		FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()`, id).
		Scan(&s.ID, &s.AccountID, &s.DeviceID, &s.FamilyID, &s.ExpiresAt, &s.RevokedAt, &s.RevokeReason, &s.FamilyStarted)
	return s, notFound(err)
}

// RevokeAuthSession revokes one session.
func RevokeAuthSession(ctx context.Context, q Q, id uuid.UUID, reason string) error {
	_, err := q.Exec(ctx, `UPDATE auth_sessions SET revoked_at = now(), revoke_reason = $2, last_used_at = now()
		WHERE id = $1 AND revoked_at IS NULL`, id, reason)
	return err
}

// RevokeAuthFamily revokes every live session of a token family.
func RevokeAuthFamily(ctx context.Context, q Q, family uuid.UUID, reason string) error {
	_, err := q.Exec(ctx, `UPDATE auth_sessions SET revoked_at = now(), revoke_reason = $2
		WHERE token_family_id = $1 AND revoked_at IS NULL`, family, reason)
	return err
}

// ---- audit ----

// Audit is one security audit event. Metadata must hold only allowlisted,
// non-secret fields.
type Audit struct {
	AccountID      *uuid.UUID
	ActorKind      string // user, phone, host, system, anonymous
	ActorDeviceID  *uuid.UUID
	TargetDeviceID *uuid.UUID
	EventType      string
	Outcome        string // success, denied, failure
	ReasonCode     string
	RequestID      string
	Metadata       map[string]any
}

// WriteAudit inserts an audit event.
func WriteAudit(ctx context.Context, q Q, a Audit) error {
	meta := a.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO audit_events (account_id, actor_kind, actor_device_id, target_device_id,
		event_type, outcome, reason_code, request_id, metadata) VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),NULLIF($8,''),$9)`,
		a.AccountID, a.ActorKind, a.ActorDeviceID, a.TargetDeviceID, a.EventType, a.Outcome, a.ReasonCode,
		truncate(a.RequestID, 64), b)
	return err
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
