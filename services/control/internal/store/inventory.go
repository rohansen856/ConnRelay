package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// DeviceFilter narrows ListDevices.
type DeviceFilter struct {
	Kind   string // "", "phone", "host"
	State  string // "", "active", "revoked"
	Prefix string // display-name prefix
	After  *uuid.UUID
	Limit  int
}

// DeviceRow is a device with the viewing phone's grant on it (hosts only).
type DeviceRow struct {
	Device
	Capabilities json.RawMessage
	MyGrant      *Grant
}

// ListDevices lists the account's devices ordered by ID (creation order).
// viewer is the calling phone; MyGrant is its active grant on each host.
func ListDevices(ctx context.Context, q Q, accountID, viewer uuid.UUID, f DeviceFilter) ([]DeviceRow, error) {
	rows, err := q.Query(ctx, `
		SELECT d.id, d.account_id, d.kind, d.platform, d.display_name, d.public_key, d.key_fingerprint,
		       d.software_version, d.admin_state, d.last_seen_at, d.enrolled_at, d.revoked_at, d.version, d.capabilities,
		       g.id, g.capabilities, g.expires_at, g.version, g.created_at
		FROM devices d
		LEFT JOIN access_grants g ON g.host_device_id = d.id AND g.phone_device_id = $2 AND g.revoked_at IS NULL
		WHERE d.account_id = $1
		  AND ($3 = '' OR d.kind = $3)
		  AND ($4 = '' OR ($4 = 'revoked') = (d.admin_state = 'revoked'))
		  AND ($5 = '' OR lower(d.display_name) LIKE lower($5) || '%')
		  AND ($6::uuid IS NULL OR d.id > $6)
		ORDER BY d.id LIMIT $7`, accountID, viewer, f.Kind, f.State, escapeLike(f.Prefix), f.After, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceRow
	for rows.Next() {
		var r DeviceRow
		var gid *uuid.UUID
		var gcaps []string
		var gexp *time.Time
		var gver *int
		var gcreated *time.Time
		if err := rows.Scan(&r.ID, &r.AccountID, &r.Kind, &r.Platform, &r.DisplayName, &r.PublicKey, &r.KeyFingerprint,
			&r.SoftwareVersion, &r.AdminState, &r.LastSeenAt, &r.EnrolledAt, &r.RevokedAt, &r.Version, &r.Capabilities,
			&gid, &gcaps, &gexp, &gver, &gcreated); err != nil {
			return nil, err
		}
		if gid != nil {
			r.MyGrant = &Grant{ID: *gid, AccountID: accountID, PhoneDeviceID: viewer, HostDeviceID: r.ID,
				Capabilities: gcaps, ExpiresAt: gexp, Version: *gver, CreatedAt: *gcreated}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func escapeLike(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '%' || r == '_' || r == '\\' {
			out = append(out, '\\')
		}
		out = append(out, r)
	}
	return string(out)
}

// RenameDevice renames a device if version matches; returns the new row.
func RenameDevice(ctx context.Context, q Q, accountID, id uuid.UUID, version int, name string) (Device, error) {
	return scanDevice(q.QueryRow(ctx, `UPDATE devices SET display_name = $4, version = version + 1
		WHERE account_id = $1 AND id = $2 AND version = $3 RETURNING `+deviceCols, accountID, id, version, name))
}

// CountActivePhones counts the account's non-revoked phones.
func CountActivePhones(ctx context.Context, q Q, accountID uuid.UUID) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM devices WHERE account_id = $1 AND kind = 'phone' AND admin_state <> 'revoked'`, accountID).Scan(&n)
	return n, err
}

// RevokeDeviceResult summarises a device revocation.
type RevokeDeviceResult struct {
	Device        Device
	GrantsRevoked int
}

// RevokeDevice revokes a device (version-checked) together with its grants,
// refresh tokens and live connection attempts. Run it inside a transaction.
func RevokeDevice(ctx context.Context, q Q, accountID, id uuid.UUID, version int, reason string, by uuid.UUID) (RevokeDeviceResult, error) {
	var r RevokeDeviceResult
	d, err := scanDevice(q.QueryRow(ctx, `UPDATE devices SET admin_state = 'revoked', revoked_at = now(), revoke_reason = $4,
		version = version + 1 WHERE account_id = $1 AND id = $2 AND version = $3 AND admin_state <> 'revoked'
		RETURNING `+deviceCols, accountID, id, version, reason))
	if err != nil {
		return r, err
	}
	r.Device = d
	tag, err := q.Exec(ctx, `UPDATE access_grants SET revoked_at = now(), revoked_by_device_id = $3, revoke_reason = 'device_revoked',
		version = version + 1 WHERE account_id = $1 AND (phone_device_id = $2 OR host_device_id = $2) AND revoked_at IS NULL`,
		accountID, id, by)
	if err != nil {
		return r, err
	}
	r.GrantsRevoked = int(tag.RowsAffected())
	if _, err := q.Exec(ctx, `UPDATE auth_sessions SET revoked_at = now(), revoke_reason = 'device_revoked'
		WHERE device_id = $1 AND revoked_at IS NULL`, id); err != nil {
		return r, err
	}
	_, err = q.Exec(ctx, `UPDATE connection_attempts SET status = 'revoked', ended_at = now()
		WHERE account_id = $1 AND (phone_device_id = $2 OR host_device_id = $2)
		  AND ended_at IS NULL
		  AND status IN ('authorized','signaling','ice_checking','relay_fallback','connected_direct','connected_relay','connected_wss')`,
		accountID, id)
	return r, err
}

// ---- grants ----

// Grant is an access grant.
type Grant struct {
	ID            uuid.UUID  `json:"id"`
	AccountID     uuid.UUID  `json:"-"`
	PhoneDeviceID uuid.UUID  `json:"phone_device_id"`
	HostDeviceID  uuid.UUID  `json:"host_device_id"`
	Capabilities  []string   `json:"capabilities"`
	ExpiresAt     *time.Time `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokeReason  *string    `json:"revoke_reason,omitempty"`
	Version       int        `json:"version"`
	CreatedAt     time.Time  `json:"created_at"`
}

const grantCols = `id, account_id, phone_device_id, host_device_id, capabilities, expires_at, revoked_at, revoke_reason, version, created_at`

func scanGrant(r interface{ Scan(...any) error }) (Grant, error) {
	var g Grant
	err := r.Scan(&g.ID, &g.AccountID, &g.PhoneDeviceID, &g.HostDeviceID, &g.Capabilities, &g.ExpiresAt, &g.RevokedAt,
		&g.RevokeReason, &g.Version, &g.CreatedAt)
	return g, notFound(err)
}

// InsertGrant creates an active grant. Both devices must be active members of
// the account; kinds are enforced by the schema.
func InsertGrant(ctx context.Context, q Q, accountID, phone, host uuid.UUID, caps []string, exp *time.Time, by uuid.UUID) (Grant, error) {
	return scanGrant(q.QueryRow(ctx, `
		INSERT INTO access_grants (id, account_id, phone_device_id, host_device_id, capabilities, expires_at, created_by_device_id)
		SELECT $1, $2, $3, $4, $5, $6, $7
		WHERE EXISTS (SELECT 1 FROM devices WHERE account_id = $2 AND id = $3 AND kind = 'phone' AND admin_state = 'active')
		  AND EXISTS (SELECT 1 FROM devices WHERE account_id = $2 AND id = $4 AND kind = 'host'  AND admin_state = 'active')
		RETURNING `+grantCols, NewID(), accountID, phone, host, caps, exp, by))
}

// GetGrant loads a grant of the account.
func GetGrant(ctx context.Context, q Q, accountID, id uuid.UUID) (Grant, error) {
	return scanGrant(q.QueryRow(ctx, `SELECT `+grantCols+` FROM access_grants WHERE account_id = $1 AND id = $2`, accountID, id))
}

// GrantFilter narrows ListGrants.
type GrantFilter struct {
	Phone, Host *uuid.UUID
	State       string // "", "active", "revoked"
}

// ListGrants lists the account's grants, newest first.
func ListGrants(ctx context.Context, q Q, accountID uuid.UUID, f GrantFilter) ([]Grant, error) {
	rows, err := q.Query(ctx, `SELECT `+grantCols+` FROM access_grants WHERE account_id = $1
		AND ($2::uuid IS NULL OR phone_device_id = $2) AND ($3::uuid IS NULL OR host_device_id = $3)
		AND ($4 = '' OR ($4 = 'revoked') = (revoked_at IS NOT NULL))
		ORDER BY created_at DESC LIMIT 500`, accountID, f.Phone, f.Host, f.State)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// SetGrantExpiry changes an active grant's expiry if version matches.
func SetGrantExpiry(ctx context.Context, q Q, accountID, id uuid.UUID, version int, exp *time.Time) (Grant, error) {
	return scanGrant(q.QueryRow(ctx, `UPDATE access_grants SET expires_at = $4, version = version + 1
		WHERE account_id = $1 AND id = $2 AND version = $3 AND revoked_at IS NULL RETURNING `+grantCols, accountID, id, version, exp))
}

// RevokeGrant revokes an active grant if version matches.
func RevokeGrant(ctx context.Context, q Q, accountID, id uuid.UUID, version int, by uuid.UUID) (Grant, error) {
	return scanGrant(q.QueryRow(ctx, `UPDATE access_grants SET revoked_at = now(), revoked_by_device_id = $4,
		revoke_reason = 'user', version = version + 1
		WHERE account_id = $1 AND id = $2 AND version = $3 AND revoked_at IS NULL RETURNING `+grantCols, accountID, id, version, by))
}

// ---- outbox ----

// Outbox queues an event for asynchronous delivery (agent notification). It
// must be called in the same transaction as the change it announces.
func Outbox(ctx context.Context, q Q, accountID uuid.UUID, aggType string, aggID uuid.UUID, event, dedupe string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO outbox_events (id, account_id, aggregate_type, aggregate_id, event_type, dedupe_key, payload)
		VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (dedupe_key) DO NOTHING`, NewID(), accountID, aggType, aggID, event, dedupe, b)
	return err
}
