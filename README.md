# security-automation-go

Go control-plane that synchronises [CrowdSec](https://crowdsec.net/) decisions to
[Cloudflare](https://www.cloudflare.com/), reports abusive IPs to
[AbuseIPDB](https://www.abuseipdb.com/), and drives WAF follow-up actions. It is
the successor to the production Python stack but is **not yet the production
authority** — see [Current status](#current-status).

> **Status: pre-cutover.** Python remains the source of truth. Go runs in
> observe-only / dry-run. Do not enable Go mutations in production until a formal
> GO is recorded against [docs/runbooks/RELEASE_CUTOVER_CHECKLIST.md](docs/runbooks/RELEASE_CUTOVER_CHECKLIST.md).

## What it replaces

The production Python stack (running from `/usr/local/bin`):

| Python script | Responsibilities |
|---|---|
| `crowdsec-cf-sync.py` | CrowdSec active-ban → Cloudflare access-rule sync, AbuseIPDB reporting, recidivist escalation, ModSecurity log scan + temp ban, `/24` auto-ban, Better Stack ingest, Cloudflare WAF GraphQL polling, JSON state |
| `cloudflare-allowlist-update.py` | Better Stack + Cloudflare IP lists → Cloudflare `allowed_ip` list; additive CrowdSec allowlist sync with exclusion pattern |
| `cloudflare-cleanup-ip-rules.py` | Paginate access rules, keep `easycron`-noted rules, delete the rest |

## Architecture

```
cmd/cf-sync            real daemon: orchestrator pipeline + WAF replay poller + HTTP API
  └── internal/orchestrator/pipeline   staged: admission → discovery → planning → execution → reporting
  └── internal/cloudflare/{transport,discovery,mutate}   real Cloudflare REST + GraphQL
  └── internal/crowdsec/adapter        real cscli execution (os/exec)
  └── internal/abuseipdb               AbuseIPDB reporting
  └── internal/runtime/*               event sourcing, journal, replay, recovery, HA lease/fencing, scheduler
  └── internal/policy                  OPA policy-as-code + explainability
  └── internal/rollback                governed, reversible mutations
  └── internal/state, internal/storage/sqlite   WAL-scoped SQLite state

cmd/{crowdsec-sync, cf-allowlist-sync, cf-cleanup}   LEGACY Phase-0 entrypoints (stub-backed; not the daemon)
```

> **Note:** `cmd/cf-sync` is the real daemon. The three thin `cmd/*` entrypoints
> and `internal/app` are Phase-0 scaffolding wired to stub clients
> (`internal/crowdsec/client.go`, `internal/cidrban`, `internal/modsecurity`,
> `internal/recidive` return `ErrNotImplemented`). They are retained for history
> and must not be deployed. See [docs/archive/TEST_GAP_REPORT.md](docs/archive/TEST_GAP_REPORT.md).

## Current status

- `go build`, `go vet`, `gofmt`, `go test`, `go test -race`: **green**.
- Test coverage is uneven: the two external-effect boundaries that actually
  change state — `internal/cloudflare/transport` (Cloudflare mutations) and
  `internal/crowdsec/adapter` (cscli bans) — currently have **no tests**.
- Several Python responsibilities are **not yet ported** to the runnable path:
  recidivist escalation, `/24` auto-ban, ModSecurity-log-based bans, and the
  allowlist-sync / cleanup flows. See [docs/archive/TEST_GAP_REPORT.md](docs/archive/TEST_GAP_REPORT.md)
  for the authoritative Python ↔ Go gap analysis.

## Build & verify

```bash
go build ./...
go vet ./...
gofmt -l .          # must print nothing
go test ./...
go test -race ./...
```

Static binaries target `CGO_ENABLED=0` (SQLite via `modernc.org/sqlite`, pure Go).

## Configuration

Environment-driven. See [pkg/configs/*.env.example](pkg/configs/). Secrets are
delivered at runtime via environment / systemd `EnvironmentFile=`; nothing
sensitive is committed.

## Deployment

Observe-only first. See [docs/runbooks/RUNBOOK.md](docs/runbooks/RUNBOOK.md) and the systemd
examples in [deployments/systemd](deployments/systemd/).

## Documentation

| Doc | Purpose |
|---|---|
| [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) | Module layout |
| [docs/runbooks/CUTOVER_RUNBOOK.md](docs/runbooks/CUTOVER_RUNBOOK.md) | Primary operational guide for the Go-Live transition |
| [docs/security/SECURITY.md](docs/security/SECURITY.md) | Reporting + operational safety |
| [docs/testing/TESTING.md](docs/testing/TESTING.md) | Guide for running and writing tests |
| [docs/archive/TEST_GAP_REPORT.md](docs/archive/TEST_GAP_REPORT.md) | Python ↔ Go gap analysis (Historical) |
| [docs/archive/MIGRATION_PLAN.md](docs/archive/MIGRATION_PLAN.md) | Migration strategy (Historical) |
| [docs/archive/RISK_ANALYSIS.md](docs/archive/RISK_ANALYSIS.md) | Migration risk register (Historical) |


## License

[Apache-2.0](LICENSE).
