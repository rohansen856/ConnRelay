# Contributing

**Status:** Draft v1. These are the working conventions for this repository. Paths marked *(planned)* do not exist yet.

## Repository layout

```text
go.work                       # Go workspace: core/prwcore, services/control, agents/host, tests
Makefile                      # vet, test, test-race, mobile, netlab, spike-s4, ci
apps/mobile/                  # Flutter app: lib/{app,core,features,widgets}, test/, android/, ios/,
                              #   gocore/build-aar.sh (gomobile AAR), third_party/xterm (vendored fork)
core/prwcore/                 # shared Go: frame, flow, attest, token, transport, peer, connmgr, control,
                              #   client (phone connect), termclient, mobile (gomobile facade)
services/control/             # control plane: cmd/prw-control (serve, check-config, keygen), cmd/prw-labserver,
                              #   internal/{auth,google,tokens,nonce,inventory,pairing,connections,hub,relay,
                              #   turncred,outbox,store,db,httpx,config,server,...}, migrations/ (goose, embedded)
agents/host/                  # host agent: cmd/prw-agent (pair, run, status, unpair, version),
                              #   internal/{agentcfg,pairclient,lease,runtime,termserver,termstream,tmux,ptyproc},
                              #   packaging/ (systemd user unit, install.sh)
protocol/vectors/             # golden test vectors (frames)
deploy/dev/                   # local development stack (devstack.sh)
deploy/{terraform,compose,coturn,caddy,scripts}/   (planned)
tests/                        # netlab (Docker NAT/TURN/proxy lab), spikes (S4, S5)
docs/                         # project documentation
.github/workflows/            # CI
```

## Toolchain

| Tool | Version | Used for |
|---|---|---|
| Go | 1.26+ (toolchain pinned to go1.27.2 via `go.mod`) | Control plane, agent, shared core |
| Flutter / Dart | 3.41.x / 3.11.x | Mobile app |
| gomobile | Latest `golang.org/x/mobile` | Binding the shared core into the app. Build with `-ldflags=-checklinkname=0` (Pion's Android interface code needs it); see `apps/mobile/gocore/build-aar.sh`. |
| Docker + Compose | 29.x | Test databases, netlab, local stack |
| tmux | ≥ 3.0 | Persistent sessions on hosts |
| PostgreSQL | 16 | Database, run in a container |
| coturn | ≥ 4.18 | TURN, run in a container |
| Terraform | ≥ 1.9 | Infrastructure (planned) |
| cloudflared | Current | Public URL for the local dev stack |
| Android SDK, Xcode (macOS) | Current stable | Mobile builds; iOS builds need macOS |

## Local development setup

The full stack (Postgres, control plane and a public HTTPS URL for a real phone) runs with `deploy/dev/devstack.sh`. The [deployment guide](../operations/deployment.md#local-development-stack) covers it in detail.

```bash
# Backend: Postgres (Docker) + control plane + Cloudflare quick tunnel
deploy/dev/devstack.sh up                 # prints the public URL; `down` stops it

# Host agent against the local control plane
go build -o ~/.local/bin/prw-agent ./agents/host/cmd/prw-agent
prw-agent pair --server "$(cat ~/.local/share/prw-dev/public_url)"
prw-agent run

# Phone app (Android device over adb)
apps/mobile/gocore/build-aar.sh
cd apps/mobile && flutter build apk --release \
  --dart-define=PRW_API="$(cat ~/.local/share/prw-dev/public_url)" \
  --dart-define=PRW_GOOGLE_SERVER_CLIENT_ID=<web client id>

# Tests
PRW_REQUIRE_DB=1 make test-race
make mobile
```

The dev stack generates throwaway keys with `prw-control keygen` into `~/.local/share/prw-dev/secrets`. Never use production secrets locally.

## Coding conventions

### Go

- Format with `gofmt`/`goimports` and lint with `golangci-lint`. The configuration lives in the repo.
- Use `internal/` packages per bounded context. Do not share packages between the control plane and the agent except through `core/prwcore`.
- Pass `context.Context` explicitly and put timeouts on all I/O. Use monotonic clocks for timeouts.
- Database access uses **pgx v5** with hand-written, parameterized SQL only. Transaction boundaries are explicit in the service layer.
- Log with `log/slog` (JSON). Use the redaction allowlist: log IDs, codes and durations, never payloads.
- Return typed errors that map to the API error catalogue. Never return stack traces to clients.
- Start processes with `exec.Command` and an argv array. **Never** concatenate strings into a shell command.

### Dart / Flutter

- Run `dart format` and `flutter analyze` with zero warnings.
- Organize code by feature under `lib/features/<feature>/`. Use Riverpod for state and go_router for navigation.
- Hide every network and transport dependency behind an interface, with a fake implementation for tests.
- Store secrets only in platform secure storage or the hardware keystore, never in shared preferences.
- UI strings must be localizable, with no concatenated sentence fragments.

### SQL migrations

- Use goose, one change per migration, forward-only in production.
- Follow expand/contract: add the new structure, migrate readers and writers, then remove the old structure in a later release.
- Migrations live in `services/control/migrations/`, are embedded in the binary and run at startup. Schema rules are tested against a real Postgres (`internal/db/schema_test.go`, using `internal/dbtest`).

## Protocol change process

The wire protocol is implemented once, in Go (`core/prwcore`), and reaches the app through the gomobile facade, so the app never re-implements framing or attestation. Every change still goes through the spec and the vectors:

1. Update the normative spec in [protocol](../technical/protocol.md) (a machine-readable `protocol/openapi.yaml` and JSON Schemas are planned).
2. Add or update the **golden vectors** in `protocol/vectors/`, as bytes or JSON together with the expected decoded values.
3. Update the Go implementation. The tests decode and re-encode every golden vector and fail on any difference.
4. Breaking changes bump the protocol version. The server keeps support for N−1 until telemetry has shown no N−1 clients for 14 days.
5. Security-relevant changes, such as attestation, tickets or pairing, need a threat-model update in the same pull request.

## Commit conventions

- **One-line [Conventional Commits](https://www.conventionalcommits.org/)** messages, in the form `<type>(<optional scope>): <summary>`, in lower case with no trailing period.
- Allowed types:

  | Type | Use for |
  |---|---|
  | `feat` | New functionality |
  | `fix` | Bug fixes |
  | `refactor` | Restructuring without behaviour change |
  | `perf` | Performance improvements |
  | `test` | Tests only |
  | `docs` | Documentation only |
  | `build` | Build system and dependencies |
  | `ci` | CI configuration |
  | `chore` | Maintenance |

- **Scope each commit tightly:**
  - Each commit carries one feature, one responsibility or one implementation step.
  - Keep commits to about **4–5 files**. Exceed that only when the change is genuinely atomic, for example generated code together with its source.
- **Sign every commit:** use `git commit -s -S`, which adds a DCO sign-off and a GPG signature.
- **No co-author trailers** in commit messages.
- Examples:

  ```text
  feat(agent): add tmux session backend
  fix(control): reject reused ticket jti
  docs: add deployment guide
  ```

## Security rules

- **Never commit secrets:** no keys, tokens, `.env` files, certificates, real domains or real account IDs. Use `example.invalid` placeholders. gitleaks runs in CI and should also run as a pre-commit hook.
- **Never log terminal content.** That includes keystrokes, output, commands, environment variables, tokens, tickets, TURN credentials, pairing codes and raw SDP. Tests enforce this with canaries.
- Pin dependencies (lockfiles, image digests, Actions by SHA). New dependencies must be under an allowed licence; AGPL is not allowed in shipped artifacts.
- No custom cryptography. Use DTLS (WebRTC), TLS 1.3, ECDSA P-256 and Ed25519 from vetted libraries only.
- The agent must never run as root.
- Report vulnerabilities privately to the maintainer. Do not open public issues for them.
