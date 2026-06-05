# Test & Functional Gap Report

**Date:** 2026-05-29
**Method:** static inspection of the Go tree (`grep`/`find`/package import tracing)
plus `go test ./...` / `go test -race ./...` results. This is evidence-based, not
a self-report; claims requiring deeper runtime validation are marked **[VERIFY]**.

**Bottom line:** the codebase **builds, vets, formats, and tests clean (incl.
`-race`)**, but it is **not ready to take production authority from Python**.
Two classes of gap block cutover: (1) the external-effect boundaries that change
real state are untested; (2) several Python responsibilities are not yet ported
to the runnable path.

---

## 1. Validation baseline (measured 2026-05-29)

| Check | Result |
|---|---|
| `go build ./...` | ✅ pass |
| `go vet ./...` | ✅ pass |
| `gofmt -l .` | ✅ clean (no output) |
| `go test ./...` | ✅ 0 failures — 56 pkgs OK, 92 pkgs no test files, 0 FAIL |
| `go test -race ./...` | ✅ pass, no data races |

**Coverage reality:** 92 of 148 packages (62%) contain **no test files**.
"`-race` clean" is therefore bounded by coverage — it proves nothing about the
62% of packages no test exercises.

---

## 2. Two coexisting code paths (conceptual-integrity risk)

| Path | Entrypoints | Backed by | State |
|---|---|---|---|
| **Real daemon** | `cmd/cf-sync` | orchestrator pipeline, `internal/cloudflare/{transport,discovery,mutate}` (real REST+GraphQL), `internal/crowdsec/adapter/cscli.go` (real `os/exec`), `internal/abuseipdb`, runtime/* | active development target |
| **Legacy Phase-0** | `cmd/crowdsec-sync`, `cmd/cf-allowlist-sync`, `cmd/cf-cleanup` → `internal/app` | **stub clients** (`internal/crowdsec/client.go`, `internal/cidrban`, `internal/modsecurity`, `internal/recidive` → `ErrNotImplemented`) | dead/no-op; must not be deployed |

**Risk:** both build and ship binaries (`bin/` had `crowdsec-sync`,
`cf-allowlist-sync`, `cf-cleanup`). Deploying a legacy binary by name would run a
no-op that silently does nothing. **Remediation before go-live:** either delete
the Phase-0 cmds + stub packages, or guard them so they refuse to run. (No
behaviour change to the real daemon — this is dead-code removal.)

---

## 3. Functional gap: Python responsibility → Go status

Legend: ✅ ported (real path) · 🟡 partial / different mechanism · ❌ not in runnable path (stub/doc only) · **[VERIFY]** needs runtime confirmation.

| Python responsibility (source) | Go owner | Status | Evidence |
|---|---|---|---|
| CrowdSec active-ban → CF access-rule sync | `cloudflare/mutate/ip_rules.go`, `crowdsec/adapter/cscli.go` | ✅ **[VERIFY]** | real POST/DELETE `/firewall/access_rules/rules`; cscli exec present |
| Cloudflare WAF GraphQL polling → ban/report | `adapters/cloudflareevent`, `cloudflare/transport` (GraphQL), WAF replay poller in `cmd/cf-sync/daemon_runtime.go` | ✅ **[VERIFY]** | `ProcessSince`, `/graphql`, cursor persistence |
| AbuseIPDB reporting | `internal/abuseipdb`, `services/reporting` | ✅ **[VERIFY]** | outbox worker, dedup, evidence |
| Recidivist escalation (2nd→24h, 3rd+→7d) | `internal/recidive` | ❌ | `ErrNotImplemented` + TODOs only; no real impl found outside stub |
| `/24` auto-ban (2+ IPs / 7d → 24h) | `internal/cidrban` | ❌ | `ErrNotImplemented` + TODOs only |
| ModSecurity log scan → temp ban (score≥5, 2h) | `internal/modsecurity` | ❌ / 🟡 | stub only; nginx-error-log path not implemented. WAF-replay is a *different* mechanism, not a substitute **[VERIFY]** |
| Allowlist sync (additive, exclusion `immuniweb`) | only `cmd/cf-allowlist-sync` (stub) | ❌ **[VERIFY]** | not found wired in `cmd/cf-sync` pipeline |
| Cleanup (keep `easycron`, delete rest) | only `cmd/cf-cleanup` (stub); `cloudflare/mutate` has delete primitives | 🟡 **[VERIFY]** | delete mutators exist; full cleanup flow not wired in daemon |
| Better Stack log ingest | `internal/betterstack`, `adapters/openrestyevent` | 🟡 **[VERIFY]** | adapters exist; end-to-end wiring unconfirmed |
| JSON state persistence | `internal/state` + `storage/sqlite` (WAL) | ✅ (re-architected) | storage migrated to SQLite; **schema/parity vs Python JSON [VERIFY]** |

> Until the ❌ rows are ported (or explicitly descoped with sign-off), **Python
> cannot be retired** — those features would silently stop.

---

## 4. Critical untested packages (go-live blockers)

External-effect & durability boundaries with **0 test files**:

| Package | Why it is critical | Required before authority switch |
|---|---|---|
| `internal/cloudflare/transport` | the code that actually mutates Cloudflare | unit + recorded-HTTP tests for POST/DELETE/GraphQL, error/retry paths |
| `internal/crowdsec/adapter` | the code that actually runs `cscli` bans | exec-wrapper tests with fake cscli, arg/quoting/parse coverage |
| `internal/runtime/ha` | lease ownership / split-brain prevention | lost-lease + fencing tests (named in GO_LIVE_CHECKLIST) |
| `internal/runtime/journal` | event durability | append/replay/corruption tests |
| `internal/runtime/replay` | deterministic replay guarantee | replay-equivalence tests |
| `internal/runtime/invariants` | runtime safety invariants | invariant-violation tests |
| `internal/runtime/scheduler` | multi-worker execution | concurrency/budget tests |
| `internal/storage`, `internal/storage/fs` | persistence | round-trip/crash tests |
| `internal/cloudflare/mutate` (1 test file) | mutation correctness | expand coverage of complex mutators / list-item paths |

Packages **with** meaningful tests already: `storage/sqlite` (8), `runtime/recovery`,
`runtime/replay/consistency`, `runtime/ownership`, `runtime/reducer`,
`runtime/state`, `security/*`, `services/reporting`, `snapshot/*`.

---

## 5. Load-bearing TODOs found in shipped code

| Location | TODO | Risk |
|---|---|---|
| `internal/rollback/planner/planner.go:82` | "Ensure this is the PREVIOUS state" | rollback may restore wrong payload — **reversibility at risk** |
| `internal/cloudflare/mutate/complex_mutators.go:117` | "Extract parent ListID" (hardcoded `""`) | list-item mutations may target wrong/empty list |
| `internal/cloudflare/client.go:87` | "Implement WAF GraphQL discovery" | discovery completeness **[VERIFY]** |
| `internal/policy/bundles/activation/manager.go` | manifest integrity / compat not verified | unsigned policy bundles could activate |
| `internal/runtime/invariants/engine.go:65` | "Integrate graph package" | invariant engine incomplete |

---

## 6. Residual risks

- **Moving Python target:** the reference Python in `~/Documents/crowdsec-cf-sync`
  is mid-refactor (StateStore extraction unmerged, `cmd_wal_replay` bug). Confirm
  parity against the **deployed** `/usr/local/bin/*.py`, not the working tree.
- **SQLite vs JSON state:** Go re-architected storage; a cold cutover cannot
  reuse Python JSON state directly — needs a documented migration or clean start.
- **Over-surface:** 148 packages for an IP-ban sync is a large untested surface to
  trust and to roll back. Favour deleting unported scaffolding over maintaining it.

---

## 7. Verdict

**NO-GO for Python retirement / Go authority.** GO for: repo + CI + observe-only
/ dry-run shadow deployment with Python authoritative and Go mutations disabled.
Exit criteria to revisit authority are in [GO_LIVE_CHECKLIST.md](GO_LIVE_CHECKLIST.md).
