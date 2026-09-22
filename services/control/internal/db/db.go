// Package db opens the PostgreSQL pool and applies migrations.
package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/rohansen856/connrelay/services/control/migrations"
)

// Open connects a pool and verifies connectivity.
func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("db: parse url: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return pool, nil
}

// Migrate applies all pending migrations.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	sqldb := stdlib.OpenDBFromPool(pool)
	defer sqldb.Close()
	return migrateDB(ctx, sqldb)
}

func migrateDB(ctx context.Context, sqldb *sql.DB) error {
	p, err := goose.NewProvider(goose.DialectPostgres, sqldb, migrations.FS)
	if err != nil {
		return err
	}
	_, err = p.Up(ctx)
	return err
}
