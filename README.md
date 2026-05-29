# security-automation-go

Go control-plane that synchronises [CrowdSec](https://crowdsec.net/) decisions to
[Cloudflare](https://www.cloudflare.com/), reports abusive IPs to
[AbuseIPDB](https://www.abuseipdb.com/), and drives WAF follow-up actions. It is
the successor to the production Python stack but is **not yet the production
authority** — see [Current status](#current-status).

> **Status: pre-cutover.** Python remains the source of truth. Go runs in
> observe-only / dry-run. Do not enable Go mutations in production until a formal
> GO is recorded against [GO_LIVE_CHECKLIST.md](GO_LIVE_CHECKLIST.md).

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
> and must not be deployed. See [TEST_GAP_REPORT.md](TEST_GAP_REPORT.md).

## Current status

- `go build`, `go vet`, `gofmt`, `go test`, `go test -race`: **green**.
- Test coverage is uneven: the two external-effect boundaries that actually
  change state — `internal/cloudflare/transport` (Cloudflare mutations) and
  `internal/crowdsec/adapter` (cscli bans) — currently have **no tests**.
- Several Python responsibilities are **not yet ported** to the runnable path:
  recidivist escalation, `/24` auto-ban, ModSecurity-log-based bans, and the
  allowlist-sync / cleanup flows. See [TEST_GAP_REPORT.md](TEST_GAP_REPORT.md)
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

Observe-only first. See [DEPLOYMENT_PLAN.md](DEPLOYMENT_PLAN.md) and the systemd
examples in [deployments/systemd](deployments/systemd/).

## Documentation

| Doc | Purpose |
|---|---|
| [DEPLOYMENT_PLAN.md](DEPLOYMENT_PLAN.md) | Phased Python→Go migration, rollback, monitoring, exit criteria |
| [GO_LIVE_CHECKLIST.md](GO_LIVE_CHECKLIST.md) | Mandatory pre-cutover validation gate |
| [TEST_GAP_REPORT.md](TEST_GAP_REPORT.md) | Python ↔ Go gap analysis + untested critical packages |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Module layout |
| [COMPATIBILITY_CHECKLIST.md](COMPATIBILITY_CHECKLIST.md) | Behaviour parity invariants |
| [RISK_ANALYSIS.md](RISK_ANALYSIS.md) | Migration risk register |
| [SECURITY.md](SECURITY.md) | Reporting + operational safety |

## License

[Apache-2.0](LICENSE).
