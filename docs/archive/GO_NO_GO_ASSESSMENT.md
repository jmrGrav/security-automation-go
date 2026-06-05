# Go / No-Go Assessment

**Date:** 2026-05-29  
**Evaluator:** SRE perspective — critical migration, not an MVP demo.  
**Sources:** PYTHON_PARITY_REPORT.md, TEST_COVERAGE_AUDIT.md, direct code reading.

---

## Verdict

> **NO-GO** for full cutover.  
> **CONDITIONAL GO** for shadow/observe mode on the AbuseIPDB reporting pipeline (features 7, 8, 9).

---

## What Is Ready

The Go codebase has real, non-trivial value. The following are production-quality:

| Component | Evidence of readiness |
|---|---|
| AbuseIPDB reporting pipeline | End-to-end: CrowdSec/OpenResty/WAF events → normalize → deduplicate → persist outbox → retry. 7 test files for `reporting` + 8 for `storage/sqlite`. |
| WAF replay cursor | Persistent cursor with overlap window — more robust than Python. |
| Circuit breaker | Tested. Prevents cascade failures. |
| Lease management | Tested. Prevents split-brain in daemon mode. |
| Execution safety (fencing, governed executor, security guard) | Tested. Pre-ban AbuseIPDB check, blast radius guard, ownership fencing. |
| SQLite storage | 8 test files covering events, leases, ownership, outbox, dedup, evidence, rollback. |
| Rollback executor | Tested. |
| Policy engine | Tested. |

---

## What Is Not Ready

### Blocker 1 — The core enforcement loop is not implemented

`crowdsec.Client.ListActiveBans()` returns `ErrNotImplemented`. This method is the entry point for the primary security enforcement job: read CrowdSec decisions, reconcile Cloudflare rules.

Without it, `cmd/crowdsec-sync` starts a daemon that processes AbuseIPDB reporting but **does not sync a single CrowdSec ban to Cloudflare**. The variable `_ = a.cs` in `CrowdSecSyncApp.Run()` is the clearest evidence: the CrowdSec client is instantiated but discarded.

**Risk if Go replaces Python here:** Active CrowdSec bans stop appearing in Cloudflare. Security posture degrades silently. No error is raised — the daemon runs normally, reporting metrics, logging clean ticks.

---

### Blocker 2 — Three commands do nothing

| Command | Expected behavior | Actual behavior |
|---|---|---|
| `cmd/cf-cleanup` | Delete expired CF rules | `CleanupApp.Run()` returns nil immediately |
| `cmd/cf-allowlist-sync` | Sync CrowdSec allowlist to CF | `AllowlistSyncApp.Run()` returns nil immediately |
| `cmd/crowdsec-sync` | Sync CrowdSec bans to CF | Processes AbuseIPDB only; CF sync not implemented |

All three would pass health checks and `go build`. A naive deployment would report success while delivering none of the expected security outcomes.

---

### Blocker 3 — Six Python features have zero Go code

- Recidive escalation (`PlaceholderService`)
- CIDR /24 auto-ban (`PlaceholderService`)
- ModSecurity log parsing (`PlaceholderService`)
- Allowlist sync (no-op)
- Cleanup (no-op)
- CrowdSec → CF sync (ErrNotImplemented)

Dropping Python while these are placeholder means losing active defense capabilities, not just monitoring.

---

### Blocker 4 — Critical execution path is 58% tested

The 11 pipeline stages that transform discovery output into CF mutations are largely untested. Specifically:

- `cloudflare/transport` (every API call) — 0 tests
- `cloudflare/discovery` — 0 tests
- `orchestrator/pipeline` normalization, planning, execution stages — 0 tests
- `crowdsec/adapter` CSCLIExecutor (runs `cscli` subprocesses) — 0 tests
- `rollback/planner` and `/validator` — 0 tests
- `runtime/drift` engine — 0 tests
- `runtime/engine` (state machine) — 0 tests

A bug in any of these silently misfires against production Cloudflare state.

---

### Blocker 5 — No integration evidence against real Cloudflare API

The test suite runs cleanly but uses no real API calls. There is one live test tag (`executor_integration_test.go`) but it tests the executor in isolation with a mock. The pipeline has never been run against a real Cloudflare zone in a controlled staging environment in this repository's history.

---

## Risk Assessment by Deployment Mode

### Observe-only (Go binaries running, writing logs/metrics only)

**Risk: LOW**  
Go services read-only, Python continues all writes. AbuseIPDB reporting runs in Go in parallel with Python. Any divergence is observable before consequences.

**Requirement:** `--dry-run=true` on cf-sync, Go AbuseIPDB pipeline operated in shadow with dedup coordination to avoid double-reporting.

---

### Shadow mode (Go runs alongside Python, both write)

**Risk: MEDIUM for AbuseIPDB pipeline, HIGH for CF mutations**  
The AbuseIPDB pipeline is ready for shadow mode. CF mutation shadow mode requires implementing `ListActiveBans()` first; without it, Go would silently do nothing while Python operates.

**Requirement for AbuseIPDB shadow:** Disable one or the other, or coordinate dedup by source tag. Both hitting AbuseIPDB for the same IP doubles report rate — potential ban on AbuseIPDB API.

---

### Controlled authority (Go takes over 1-2 features, Python covers the rest)

**Risk: LOW for AbuseIPDB reporting, HIGH for anything else**  
Go AbuseIPDB pipeline can own reporting today if dedup is verified. Everything else requires implementation first.

**What Go can own now:** CrowdSec/OpenResty/WAF event → AbuseIPDB path only.  
**What Python must keep:** CS → CF sync, allowlist sync, cleanup, recidive, CIDR /24, ModSec.

---

### Full cutover

**Risk: CRITICAL — not recommended.**  
Six features are stub/no-op. Cutting over means: no enforcement sync, no cleanup, no allowlist sync, no recidive, no CIDR auto-ban, no ModSec reporting. Security posture would degrade within hours.

---

## Migration Recommendation

**Immediate (no blockers):**  
Deploy `cmd/crowdsec-sync` in controlled authority mode for **AbuseIPDB reporting only** — feature #7 (CrowdSec events) and #8 (OpenResty events). Stop Python's equivalent inline reporting for these sources. Monitor for dedup collisions and report rate changes. This is the only feature area where Go is demonstrably superior to Python today.

**Short-term prerequisites before any CF mutation authority:**
1. Implement `crowdsec.Client.ListActiveBans()` — the entry point for the enforcement loop.
2. Implement `CleanupApp.Run()` with real CF rule TTL cleanup.
3. Run the pipeline end-to-end against a staging Cloudflare zone and capture a diff report.
4. Test `crowdsec/adapter.CSCLIExecutor` — it runs shell commands that modify CrowdSec state.

**Medium-term prerequisites before Python decommission:**
5. Implement recidive, CIDR /24, ModSec (or formally accept these as deferred).
6. Implement allowlist sync.
7. Add integration tests covering the full pipeline (discovery → normalization → planning → execution → rollback path).
8. Run in full shadow mode for ≥2 weeks with diff comparison against Python outputs.

**Estimated operational risk if cut over today:** HIGH. Silent enforcement gap on the core ban sync within hours of Python stop.

---

## Honest Assessment

The Go codebase is architecturally sound — the control plane infrastructure (circuit breaker, lease, rollback, policy engine, event sourcing, SQLite storage) is more mature than what Python has. The problem is that the **data layer connecting CrowdSec to this infrastructure is missing**. The pipes are built; nothing flows through them yet.

The AbuseIPDB reporting pipeline is the exception — it is production-quality and Go-ready today.

The path to full cutover is clear and achievable, but it requires implementing the missing data sources and validating with real API traffic before Python can be turned off.
