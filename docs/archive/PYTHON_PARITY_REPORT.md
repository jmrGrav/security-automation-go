# Python Parity Report

**Date:** 2026-05-29  
**Scope:** Factual comparison only — no code was written.  
**Method:** Direct code reading of `internal/app/app.go`, `cmd/cf-sync/main.go`, `cmd/cf-sync/runtime_wiring.go`, `internal/app/reporting_runtime.go`, and all referenced service packages.

---

## How to Read This Report

Each row maps a Python production feature to its Go equivalent, based on actual code paths — not documentation or design intent. "Partially covered" means the Go code compiles and runs but does not yet deliver the same operational outcome as the Python feature.

---

## Feature Parity Table

| # | Feature | Python entry point | Go entry point | Status |
|---|---|---|---|---|
| 1 | CrowdSec bans → Cloudflare IP access rules | `cs_to_cf.py` | `cmd/crowdsec-sync` + `app.CrowdSecSyncApp` | **NOT COVERED** |
| 2 | Allowlist sync (CrowdSec ↔ Cloudflare) | `allowlist_sync.py` | `cmd/cf-allowlist-sync` + `app.AllowlistSyncApp` | **NOT COVERED** |
| 3 | Cleanup expired Cloudflare rules | `cleanup.py` | `cmd/cf-cleanup` + `app.CleanupApp` | **NOT COVERED** |
| 4 | Recidive escalation (2nd → 24h, 3rd+ → 7d) | `recidive.py` | `internal/recidive.PlaceholderService` | **NOT COVERED** |
| 5 | CIDR /24 auto-ban (2+ IPs in subnet) | `cidr_ban.py` | `internal/cidrban.PlaceholderService` | **NOT COVERED** |
| 6 | ModSecurity log → AbuseIPDB | `modsecurity_abuse.py` | `internal/modsecurity.PlaceholderService` | **NOT COVERED** |
| 7 | CrowdSec decisions.log → AbuseIPDB | `abuse_ipdb.py` (cs source) | `internal/adapters/crowdsecevent` + `reporting_runtime.processCrowdSec` | **COVERED** |
| 8 | OpenResty events → AbuseIPDB | `abuse_ipdb.py` (openresty source) | `internal/adapters/openrestyevent` + `reporting_runtime.processOpenResty` | **COVERED** |
| 9 | Cloudflare WAF events → AbuseIPDB (replay) | `waf_replay.py` | `internal/adapters/cloudflareevent` + WAF replay poller in `cmd/cf-sync` daemon | **COVERED** |
| 10 | AbuseIPDB outbox (retry, dedup, evidence) | (Python posts inline, no outbox) | `internal/services/reporting` + `storage/sqlite` outbox | **COVERED — exceeds Python** |
| 11 | CrowdSec bans via cscli (execution layer) | `cscli` subprocess calls | `internal/crowdsec/adapter.CSCLIExecutor` | **PARTIALLY COVERED** |

---

## Detailed Analysis by Feature

### 1. CrowdSec bans → Cloudflare IP access rules — NOT COVERED

**Python behavior:** Reads active CrowdSec decisions (`cscli decisions list -o json`), filters by local origin, maps IPs to Cloudflare IP access rules, creates/deletes rules to converge state.

**Go reality:**
- `crowdsec.Client.ListActiveBans()` → always returns `ErrNotImplemented`.
- `CrowdSecSyncApp.Run()` in `internal/app/app.go` executes a scheduler loop but the `_ = a.cs` line confirms the CrowdSec client is ignored at runtime.
- The `cmd/cf-sync` pipeline orchestrator does CF → CF reconciliation (discovers current CF state, plans mutations against desired policy state), but the CrowdSec source of decisions is not wired in as input.

**Gap:** No Go code path reads CrowdSec decisions and converts them to Cloudflare mutations.

---

### 2. Allowlist sync (CrowdSec ↔ Cloudflare) — NOT COVERED

**Python behavior:** Reads the CrowdSec allowlist (`cscli allowlists inspect`), compares against Cloudflare IP lists, adds/removes entries to converge.

**Go reality:**
- `crowdsec.Client.ListAllowlist()` → `ErrNotImplemented`.
- `crowdsec.Client.AddAllowlistEntry()` → `ErrNotImplemented`.
- `AllowlistSyncApp.Run()` body: `_ = a.cf; _ = a.cs; return nil`. Literally no-op.

**Gap:** Binary starts but does nothing.

---

### 3. Cleanup expired Cloudflare rules — NOT COVERED

**Python behavior:** Lists Cloudflare IP access rules, identifies those past their TTL, deletes them.

**Go reality:**
- `CleanupApp.Run()` body: `_ = a.cf; return nil`. No-op.

**Gap:** Binary starts but does nothing.

---

### 4. Recidive escalation — NOT COVERED

**Python behavior:** Monitors `recidivists.json`, detects IPs with 2+ bans in a window, escalates ban durations (24h on 2nd, 7d on 3rd+) via `cscli`.

**Go reality:**
- `recidive.PlaceholderService.Run()` → `ErrNotImplemented`.
- TODO comments list the full intended algorithm.

**Gap:** Stub only.

---

### 5. CIDR /24 auto-ban — NOT COVERED

**Python behavior:** Groups IPs banned in a 7-day window by /24 subnet. If 2+ IPs from the same /24 are banned, bans the entire /24 for 24h in both Cloudflare and CrowdSec.

**Go reality:**
- `cidrban.PlaceholderService.Run()` → `ErrNotImplemented`.

**Gap:** Stub only.

---

### 6. ModSecurity log → AbuseIPDB — NOT COVERED

**Python behavior:** Parses nginx error log for ModSecurity events with score ≥ 5, reports to AbuseIPDB, adds 2h Cloudflare ban.

**Go reality:**
- `modsecurity.PlaceholderService.Run()` → `ErrNotImplemented`.

**Gap:** Stub only.

---

### 7. CrowdSec decisions.log → AbuseIPDB — COVERED

**Python behavior:** Reads CrowdSec decisions log, reports IPs to AbuseIPDB.

**Go implementation:**
- `crowdsecevent.NewLiveSource(cfg.CrowdSec.DecisionsLog, ...)` reads the decisions log file.
- `crowdsecevent.Service.Process()` normalizes events.
- `reporting.Service.Process()` handles dedup, trust filtering, and AbuseIPDB reporting.
- SQLite-backed outbox persists undelivered reports and retries with backoff.
- `reporting_runtime.processCrowdSec()` is called in the `CrowdSecSyncApp` scheduler loop.

**Exceeds Python:** Go adds dedup (24h window), trust scoring, false-positive memory, evidence persistence, and BetterStack telemetry. Python reports inline without retry or persistence.

---

### 8. OpenResty events → AbuseIPDB — COVERED

**Python behavior:** Reads OpenResty/Lua status file, reports security events to AbuseIPDB.

**Go implementation:**
- `openrestyevent.NewLiveSource(cfg.OpenResty.EventsFile)` reads the events file.
- `openrestyevent.Service.Process()` normalizes and routes through `reporting.Service`.
- Same dedup/outbox/telemetry pipeline as feature 7.

---

### 9. Cloudflare WAF events → AbuseIPDB (replay) — COVERED

**Python behavior:** Polls Cloudflare WAF Firewall Events API, classifies blocked requests, reports to AbuseIPDB.

**Go implementation:**
- `cloudflareevent.Service.ProcessSince()` fetches WAF events via `ListWAFEventsSince`.
- Normalizes via `cloudflareevent.Normalize()`.
- Persistent cursor stored in SQLite (`cursor_store`) survives restarts.
- 10-minute overlap window prevents gaps on restart.
- Reports via `reporting.Service` (same dedup/outbox as 7/8).
- WAF replay poller runs in daemon mode via `startWAFReplayPoller()`.

**Exceeds Python:** Persistent cursor, 10-min overlap, dedup, evidence trail.

---

### 10. AbuseIPDB outbox — COVERED, exceeds Python

**Python behavior:** No outbox. Python reports inline. On failure, the report is lost.

**Go implementation:** Failed/pending AbuseIPDB reports are persisted in SQLite, retried with backoff via `OutboxWorker`, deduplicated with a 24-hour window by IP+category. Evidence (what was reported, when, why) is stored and queryable.

---

### 11. CrowdSec bans via cscli (execution layer) — PARTIALLY COVERED

**Python behavior:** Calls `cscli decisions add/delete` subprocess.

**Go implementation:**
- `crowdsec/adapter.CSCLIExecutor.Execute()` wraps `cscli` subprocess calls with per-action timeout, idempotence detection, and audit trail.
- `crowdsec/adapter.DryRunExecutor` for safe preview.
- **However:** This executor is only reachable if the discovery layer (`ListActiveBans`) feeds it decisions. Since that layer is not implemented, the executor is currently unreachable in production. It is wired but not driven.

---

## Summary

| Coverage | Count | Features |
|---|---|---|
| **Covered** | 4 | CrowdSec→AbuseIPDB, OpenResty→AbuseIPDB, WAF replay, Outbox |
| **Partially covered** | 1 | cscli execution layer (executor built, data source absent) |
| **Not covered** | 6 | CS→CF sync, Allowlist sync, Cleanup, Recidive, CIDR /24, ModSec |

---

## Critical Gap: The Core Python Job Is Not Running in Go

The most critical Python job is `cs_to_cf.py`: read CrowdSec bans, push to Cloudflare. This is the primary security enforcement loop.

**This loop does not exist in Go yet.** The plumbing (reconciliation, execution, rollback, policy engine, SQLite) is built and tested. The missing piece is the data source: `crowdsec.Client.ListActiveBans()` must be implemented before the Go control plane can take over this responsibility.

Until then, Python remains the sole operator of the enforcement loop.
