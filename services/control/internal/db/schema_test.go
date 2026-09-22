package db_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rohansen856/connrelay/services/control/internal/dbtest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	dbtest.Cleanup()
	os.Exit(code)
}

var ctx = context.Background()

func id() uuid.UUID { return uuid.Must(uuid.NewV7()) }

func account(t *testing.T, p *pgxpool.Pool) uuid.UUID {
	t.Helper()
	a := id()
	if _, err := p.Exec(ctx, `INSERT INTO accounts (id, identity_provider, identity_subject) VALUES ($1,'google',$2)`, a, a.String()); err != nil {
		t.Fatal(err)
	}
	return a
}

func device(t *testing.T, p *pgxpool.Pool, acct uuid.UUID, kind string) uuid.UUID {
	t.Helper()
	d := id()
	key := make([]byte, 91)
	_, _ = rand.Read(key)
	fp := sha256.Sum256(key)
	platform := map[string]string{"phone": "android", "host": "linux"}[kind]
	if _, err := p.Exec(ctx, `INSERT INTO devices (id, account_id, kind, platform, display_name, public_key, key_fingerprint)
		VALUES ($1,$2,$3,$4,'dev',$5,$6)`, d, acct, kind, platform, key, hex.EncodeToString(fp[:])); err != nil {
		t.Fatal(err)
	}
	return d
}

func grant(p *pgxpool.Pool, acct, phone, host uuid.UUID) error {
	_, err := p.Exec(ctx, `INSERT INTO access_grants (id, account_id, phone_device_id, host_device_id) VALUES ($1,$2,$3,$4)`,
		id(), acct, phone, host)
	return err
}

// sqlState returns the PostgreSQL error code, e.g. 23503 (foreign key).
func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func TestGrantMustStayInsideOneAccount(t *testing.T) {
	p := dbtest.New(t)
	a, b := account(t, p), account(t, p)
	phoneA := device(t, p, a, "phone")
	hostB := device(t, p, b, "host")
	// Claiming either account must fail: the composite FK includes account_id.
	if err := grant(p, a, phoneA, hostB); sqlState(err) != "23503" {
		t.Fatalf("cross-account grant (claimed A): %v", err)
	}
	if err := grant(p, b, phoneA, hostB); sqlState(err) != "23503" {
		t.Fatalf("cross-account grant (claimed B): %v", err)
	}
}

func TestGrantEnforcesDeviceKinds(t *testing.T) {
	p := dbtest.New(t)
	a := account(t, p)
	phone, host := device(t, p, a, "phone"), device(t, p, a, "host")
	if err := grant(p, a, host, phone); sqlState(err) != "23503" {
		t.Fatalf("grant with swapped kinds: %v", err)
	}
	other := device(t, p, a, "phone")
	if err := grant(p, a, phone, other); sqlState(err) != "23503" {
		t.Fatalf("phone-to-phone grant: %v", err)
	}
	if err := grant(p, a, phone, host); err != nil {
		t.Fatalf("valid grant: %v", err)
	}
}

func TestOneActiveGrantPerPair(t *testing.T) {
	p := dbtest.New(t)
	a := account(t, p)
	phone, host := device(t, p, a, "phone"), device(t, p, a, "host")
	if err := grant(p, a, phone, host); err != nil {
		t.Fatal(err)
	}
	if err := grant(p, a, phone, host); sqlState(err) != "23505" {
		t.Fatalf("second active grant: %v", err)
	}
	if _, err := p.Exec(ctx, `UPDATE access_grants SET revoked_at = now() WHERE phone_device_id=$1`, phone); err != nil {
		t.Fatal(err)
	}
	if err := grant(p, a, phone, host); err != nil {
		t.Fatalf("re-grant after revoke: %v", err)
	}
}

func TestGrantCapabilitiesValidated(t *testing.T) {
	p := dbtest.New(t)
	a := account(t, p)
	phone, host := device(t, p, a, "phone"), device(t, p, a, "host")
	_, err := p.Exec(ctx, `INSERT INTO access_grants (id, account_id, phone_device_id, host_device_id, capabilities)
		VALUES ($1,$2,$3,$4,ARRAY['root_shell'])`, id(), a, phone, host)
	if sqlState(err) != "23514" {
		t.Fatalf("unknown capability: %v", err)
	}
}

func TestDevicesAreNeverHardDeletedWithHistory(t *testing.T) {
	p := dbtest.New(t)
	a := account(t, p)
	phone, host := device(t, p, a, "phone"), device(t, p, a, "host")
	if err := grant(p, a, phone, host); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `DELETE FROM devices WHERE id=$1`, host); sqlState(err) != "23503" {
		t.Fatalf("delete of device with grants: %v", err)
	}
}

func TestRevokedStateIsConsistent(t *testing.T) {
	p := dbtest.New(t)
	a := account(t, p)
	d := device(t, p, a, "phone")
	if _, err := p.Exec(ctx, `UPDATE devices SET admin_state='revoked' WHERE id=$1`, d); sqlState(err) != "23514" {
		t.Fatalf("revoked without revoked_at: %v", err)
	}
	if _, err := p.Exec(ctx, `UPDATE devices SET admin_state='revoked', revoked_at=now(), revoke_reason='lost' WHERE id=$1`, d); err != nil {
		t.Fatal(err)
	}
}

func TestLiveKeyFingerprintUniquePerAccount(t *testing.T) {
	p := dbtest.New(t)
	a := account(t, p)
	d := device(t, p, a, "host")
	var key []byte
	var fp string
	_ = p.QueryRow(ctx, `SELECT public_key, key_fingerprint FROM devices WHERE id=$1`, d).Scan(&key, &fp)
	insert := func() error {
		_, err := p.Exec(ctx, `INSERT INTO devices (id, account_id, kind, platform, display_name, public_key, key_fingerprint)
			VALUES ($1,$2,'host','linux','dup',$3,$4)`, id(), a, key, fp)
		return err
	}
	if err := insert(); sqlState(err) != "23505" {
		t.Fatalf("duplicate live key: %v", err)
	}
	_, _ = p.Exec(ctx, `UPDATE devices SET admin_state='revoked', revoked_at=now() WHERE id=$1`, d)
	if err := insert(); err != nil {
		t.Fatalf("re-enrol same key after revoke: %v", err)
	}
}

func TestAuthSessionsOnlyForPhones(t *testing.T) {
	p := dbtest.New(t)
	a := account(t, p)
	host := device(t, p, a, "host")
	_, err := p.Exec(ctx, `INSERT INTO auth_sessions (id, account_id, device_id, token_family_id, refresh_token_hash, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)`, id(), a, host, id(), []byte("h"), time.Now().Add(time.Hour))
	if sqlState(err) != "23503" {
		t.Fatalf("auth session for a host: %v", err)
	}
}

func TestUpdatedAtTrigger(t *testing.T) {
	p := dbtest.New(t)
	a := account(t, p)
	var before, after time.Time
	_ = p.QueryRow(ctx, `SELECT updated_at FROM accounts WHERE id=$1`, a).Scan(&before)
	time.Sleep(20 * time.Millisecond)
	_ = p.QueryRow(ctx, `UPDATE accounts SET display_name='x' WHERE id=$1 RETURNING updated_at`, a).Scan(&after)
	if !after.After(before) {
		t.Fatalf("updated_at not bumped: %v -> %v", before, after)
	}
}

func TestDatabasesAreIsolated(t *testing.T) {
	p1, p2 := dbtest.New(t), dbtest.New(t)
	account(t, p1)
	var n int
	_ = p2.QueryRow(ctx, `SELECT count(*) FROM accounts`).Scan(&n)
	if n != 0 {
		t.Fatalf("second database sees %d accounts", n)
	}
}
