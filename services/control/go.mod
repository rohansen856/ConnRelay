module github.com/rohansen856/connrelay/services/control

go 1.26.0

toolchain go1.27.2

require (
	github.com/coder/websocket v1.8.15
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/go-jose/go-jose/v4 v4.1.5
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.11.0
	github.com/pressly/goose/v3 v3.29.0
	github.com/rohansen856/connrelay/core/prwcore v0.0.0
	golang.org/x/time v0.15.0
)

require (
	github.com/gowebpki/jcs v1.0.2 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/sethvargo/go-retry v0.5.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/rohansen856/connrelay/core/prwcore => ../../core/prwcore
