# Documentation

| Document | What it covers |
|---|---|
| **Architecture** | |
| [architecture/overview.md](architecture/overview.md) | Components, trust boundaries, main flows, failure behavior |
| [architecture/decisions.md](architecture/decisions.md) | Architecture decision records (ADR-001 to ADR-012) |
| **Technical** | |
| [technical/protocol.md](technical/protocol.md) | Pairing, tickets, signaling, relay, attestation, framing, flow control |
| [technical/security.md](technical/security.md) | Security model, threats, compromise playbooks, logging policy |
| [technical/data-model.md](technical/data-model.md) | PostgreSQL schema, integrity rules, retention, migrations |
| [technical/api.md](technical/api.md) | REST and WebSocket API reference |
| **Components** | |
| [components/control-plane.md](components/control-plane.md) | Go control plane |
| [components/host-agent.md](components/host-agent.md) | Linux host agent and tmux session manager |
| [components/mobile-app.md](components/mobile-app.md) | Flutter phone app |
| [components/prwcore.md](components/prwcore.md) | Shared Go protocol and transport core |
| **Operations** | |
| [operations/deployment.md](operations/deployment.md) | AWS deployment, coturn, TLS, backups, CI/CD |
| [operations/runbooks.md](operations/runbooks.md) | Operational procedures and incident response |
| **Development** | |
| [development/contributing.md](development/contributing.md) | Repository layout, conventions, commit rules |
| [development/testing.md](development/testing.md) | Test strategy, network lab, release gates |
| **Planning** | |
| [roadmap.md](roadmap.md) | MVP scope, delivery phases, post-MVP roadmap |
