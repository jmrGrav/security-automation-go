# security-automation-go

![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)
![CI](https://github.com/jmrGrav/security-automation-go/actions/workflows/ci.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/jmrGrav/security-automation-go)
![License](https://img.shields.io/github/license/jmrGrav/security-automation-go)
![Security](https://img.shields.io/badge/security-policy-green)

Go control-plane that synchronises [CrowdSec](https://crowdsec.net/) decisions to
[Cloudflare](https://www.cloudflare.com/), reports abusive IPs to
[AbuseIPDB](https://www.abuseipdb.com/), and drives WAF follow-up actions.

> **Status: v1.5.0 — first-run install and Go runtime cutover-ready.**
> The historical Python runtime is retired from the critical path; remaining legacy
> scripts are kept only for rollback or archival reference.
> Recidivist escalation and `/24` auto-ban remain in Python stubs (backlog v1.5.1).

## What it replaces

The production Python stack:

| Python script | Go replacement |
|---|---|
| `crowdsec-cf-sync.py` | `cmd/cf-sync` — CrowdSec → Cloudflare pipeline, AbuseIPDB reporting, BetterStack ingest, WAF GraphQL polling |
| `crowdsec-poller.py` | `internal/crowdsec/poller/` — Go port; LAPI key from encrypted CredentialStore |
| `cloudflare-allowlist-update.py` | `cmd/cf-allowlist-sync` |
| `cloudflare-cleanup-ip-rules.py` | `cmd/cf-cleanup` |
| ModSecurity log scan + temp ban | **Retired** — replaced by CrowdSec AppSec |

## Architecture

```
cmd/cf-sync            main daemon: orchestrator pipeline + WAF replay poller + operator UI
  └── internal/orchestrator/pipeline   staged: admission → discovery → planning → execution → reporting
  └── internal/cloudflare/{transport,discovery,mutate}   Cloudflare REST + GraphQL
  └── internal/crowdsec/{adapter,poller}  cscli execution + LAPI polling
  └── internal/abuseipdb               AbuseIPDB reporting
  └── internal/runtime/*               event sourcing, journal, replay, recovery, HA fencing, scheduler
  └── internal/storage/sqlite          WAL-scoped SQLite state + encrypted CredentialStore (AES-GCM)
  └── internal/ui                      operator web UI, first-run wizard, health center
  └── internal/health, internal/detect component health checks + auto-discovery

cmd/{crowdsec-sync, cf-allowlist-sync, cf-cleanup}   thin entrypoints (phase-0 scaffolding)
```

## Current status

- `go build`, `go vet`, `gofmt`, `go test`, `go test -race`: **green**.
- First-run wizard: **validated** end-to-end (`TestUIFreshInstallWizardAndConservativeRestart`).
- Encrypted CredentialStore: **production-ready**. All secrets flow through SQLite AES-GCM.
- CrowdSec Go integration: **complete** (detection, health, admin UI, wizard, poller).
- External-effect boundaries (`internal/cloudflare/transport`, `internal/crowdsec/adapter`) have integration tests via the running daemon; no isolated unit tests yet.
- Recidivist escalation, `/24` auto-ban, and ModSecurity-based bans: Python stubs (`ErrNotImplemented`), backlog v1.5.1.

## Build & verify

```bash
go build ./...
go vet ./...
gofmt -l .           # must print nothing
go test ./...
go test -race ./...
make package         # builds dist/security-automation-go_1.5.0_amd64.deb
```

Static binaries (`CGO_ENABLED=0`). SQLite via `modernc.org/sqlite` (pure Go, no CGo).

## Configuration

Secrets are delivered exclusively via the **encrypted CredentialStore** (SQLite AES-GCM).
The first-run wizard writes all secrets interactively; nothing sensitive is committed.

See [docs/configuration/](docs/configuration/) for provider-specific guides.

## Deployment

```bash
# Install .deb
sudo dpkg -i dist/security-automation-go_1.5.0_amd64.deb
sudo systemctl start cf-sync

# Or run the wizard manually
cf-sync --setup
```

First-run wizard runs automatically on fresh install. See [docs/runbooks/FIRST_BOOT.md](docs/runbooks/FIRST_BOOT.md).

## Documentation

| Doc | Purpose |
|---|---|
| [docs/AI_HANDOFF.md](docs/AI_HANDOFF.md) | Rapid context for AI assistants and contributors |
| [docs/runbooks/FIRST_BOOT.md](docs/runbooks/FIRST_BOOT.md) | First-boot install procedure |
| [docs/runbooks/RUNBOOK.md](docs/runbooks/RUNBOOK.md) | Primary operational guide |
| [docs/runbooks/CUTOVER_RUNBOOK.md](docs/runbooks/CUTOVER_RUNBOOK.md) | Python → Go cutover runbook |
| [docs/security/SECRET_LOADING_MODEL.md](docs/security/SECRET_LOADING_MODEL.md) | Secret loading audit |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |

## License

[Apache-2.0](LICENSE).
