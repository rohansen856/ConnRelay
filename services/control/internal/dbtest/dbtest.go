// Package dbtest provides migrated, isolated PostgreSQL databases for tests.
//
// Set CONNRELAY_TEST_DATABASE_URL to an admin URL of an existing server (CI service
// container). Otherwise a postgres:16-alpine container is started with Docker
// once per test binary and removed when it exits. Tests skip when neither is
// available, unless CONNRELAY_REQUIRE_DB=1 (CI), which makes them fail.
package dbtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rohansen856/connrelay/services/control/internal/db"
)

const template = "connrelay_template"

var (
	once     sync.Once
	adminURL string
	setupErr error
)

func setup() {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	adminURL = os.Getenv("CONNRELAY_TEST_DATABASE_URL")
	if adminURL == "" {
		// Docker occasionally leaves a container in "created"; retry once.
		for try := 0; try < 2; try++ {
			if adminURL, setupErr = startContainer(ctx); setupErr == nil {
				break
			}
		}
		if setupErr != nil {
			return
		}
	}
	admin, err := waitReady(ctx, adminURL)
	if err != nil {
		setupErr = err
		return
	}
	defer admin.Close()
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+template)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+template); err != nil {
		setupErr = err
		return
	}
	tp, err := db.Open(ctx, withDB(adminURL, template))
	if err != nil {
		setupErr = err
		return
	}
	setupErr = db.Migrate(ctx, tp)
	tp.Close()
}

func startContainer(ctx context.Context) (string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", fmt.Errorf("docker not available: %w", err)
	}
	out, err := exec.CommandContext(ctx, "docker", "run", "-d", "--rm", "-P",
		"-e", "POSTGRES_PASSWORD=test", "-e", "POSTGRES_USER=connrelay",
		"--label", "connrelay-dbtest=1", "postgres:16-alpine").Output()
	if err != nil {
		return "", fmt.Errorf("start postgres: %w", err)
	}
	id := strings.TrimSpace(string(out))
	containers.Lock()
	containers.ids = append(containers.ids, id)
	containers.Unlock()
	state, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Running}}", id).Output()
	if err != nil || strings.TrimSpace(string(state)) != "true" {
		_ = exec.Command("docker", "rm", "-f", id).Run()
		return "", fmt.Errorf("postgres container did not start")
	}
	port, err := exec.CommandContext(ctx, "docker", "port", id, "5432/tcp").Output()
	if err != nil {
		return "", err
	}
	hostPort := strings.TrimSpace(strings.Split(string(port), "\n")[0])
	hostPort = strings.Replace(hostPort, "0.0.0.0", "127.0.0.1", 1)
	return "postgres://connrelay:test@" + hostPort + "/postgres?sslmode=disable", nil
}

var containers struct {
	sync.Mutex
	ids []string
}

// Cleanup stops containers started by this package. Call it from TestMain.
func Cleanup() {
	containers.Lock()
	defer containers.Unlock()
	for _, id := range containers.ids {
		_ = exec.Command("docker", "stop", "-t", "1", id).Run()
	}
	containers.ids = nil
}

func waitReady(ctx context.Context, u string) (*pgxpool.Pool, error) {
	var last error
	for ctx.Err() == nil {
		p, err := db.Open(ctx, u)
		if err == nil {
			return p, nil
		}
		last = err
		time.Sleep(300 * time.Millisecond)
	}
	return nil, fmt.Errorf("postgres not ready: %v", last)
}

func withDB(u, name string) string {
	pu, _ := url.Parse(u)
	pu.Path = "/" + name
	return pu.String()
}

// New returns a pool on a fresh, fully migrated database dropped after t.
func New(t testing.TB) *pgxpool.Pool {
	t.Helper()
	once.Do(setup)
	if setupErr != nil {
		// CI sets CONNRELAY_REQUIRE_DB=1 so a missing database fails loudly
		// instead of silently skipping every database test.
		if os.Getenv("CONNRELAY_REQUIRE_DB") == "1" {
			t.Fatalf("no test database: %v", setupErr)
		}
		t.Skipf("no test database: %v", setupErr)
	}
	ctx := context.Background()
	admin, err := db.Open(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	name := "t_" + hex.EncodeToString(b[:])
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name+" TEMPLATE "+template); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	pool, err := db.Open(ctx, withDB(adminURL, name))
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		admin.Close()
	})
	return pool
}
