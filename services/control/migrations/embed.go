// Package migrations embeds the goose SQL migrations for the control plane.
// Migrations are forward-only in production; Down sections exist for local
// development and tests.
package migrations

import "embed"

// FS holds the *.sql migrations.
//
//go:embed *.sql
var FS embed.FS
