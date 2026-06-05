# Python Feature Matrix

**Date:** 2026-05-30 (updated after Priority 1–4 verification)  
**Python reference:** github.com/jmrGrav/crowdsec-cf-sync (V4 / main.py)  
**Go entry points:** cmd/cf-sync (orchestrator daemon), cmd/crowdsec-sync, cmd/cf-allowlist-sync, cmd/cf-cleanup

Status legend: ✅ Implemented | ⚠️ Partial | ❌ Missing

---

## Core Enforcement Loop

| Feature | Python function | Go location | Status | Notes |
|---|---|---|---|---|
| Fetch active CrowdSec bans | `get_active_bans()` → `_fetch_all_cscli_decisions()` | `crowdsec.Client.ListActiveBans()` | ✅ | cscli + fixture backends; no --origin flag (CrowdSec bug #4470) |
| Filter LOCAL_ORIGINS | `_cscli_bans_for_origin()` | `source.FilterActiveBanIPs()` | ✅ | origin ∈ {"crowdsec","cscli"}, type=ban, scope.lower()=ip |
| Sync active bans → CF IP rules | `sync_cloudflare()` | `app.CrowdSecSyncApp.syncCloudflare()` | ✅ | Add/delete with 100ms courtesy sleep; IP normalization |
| CIDR-aware reconciliation | `reconcile_state()` | `app.CleanupApp.Run()` | ✅ | Cleanup removes stale crowdsec-local-ban rules |
| Anti-self-ban (protected ranges) | `is_protected()` + `_build_protected_networks()` | `security/protected.Shield` | ✅ | RFC1918 + Cloudflare CIDRs + `ip -j addr` auto-detect; wired in buildSyncPlan + cidrBanSourceAdapter |
| Allowlist filter in enforcement | `is_allowlisted()` in `sync_cloudflare()` | `app.allowlistSet.contains()` in `buildSyncPlan()` | ✅ | **IMPLEMENTED 2026-05-30** — direct IP + CIDR coverage; fail-open on fetch error |
| Allowlist filter in CIDR path | `is_allowlisted()` in `sync_cidr_bans()` | `cidrBanSourceAdapter.ListRecentBans()` | ✅ | **IMPLEMENTED 2026-05-30** — same allowlistSet applied before /24 grouping |
| Adaptive mitigation (confidence gate) | `_should_sync_to_cf()` | ❌ not ported | ❌ | **VERIFIED: no current production drift** — see Confidence Gate section below |
| Rule collapsing (collapse_ips) | `collapse_ips()` | ❌ not ported | ❌ | Python collapses adjacent /32s → /24 when many IPs share prefix |
| CF quota warning (800/1000 rules) | `_fetch_cf_rules()` quota check | ❌ not ported | ❌ | |

---

## CrowdSec Data Sources

| Feature | Python function | Go location | Status | Notes |
|---|---|---|---|---|
| Read recent bans from decisions.log | `get_recent_local_bans()` | `crowdsec.Client.ListRecentBans()` | ✅ | 48h window; handles event_type alert+decision |
| Parse decisions.log format | inline in `get_recent_local_bans()` | `crowdsec.Client.ListRecentBans()` | ✅ | ISO datetime, cloudflare-waf + recidivist filters |
| Read CrowdSec allowlist | `get_crowdsec_allowlist()` | `crowdsec.Client.ListAllowlist()` | ✅ | cscli allowlists inspect <name> -o json |
| Add CrowdSec allowlist entry | _(not in Python main loop)_ | `crowdsec.Client.AddAllowlistEntry()` | ✅ | |
| Add IP decision via cscli | `escalate_ban()` | `crowdsec.Client.AddIPDecision()` | ✅ | |
| Add range decision via cscli | `sync_cidr_bans()` → subprocess | `crowdsec.Client.AddRangeDecision()` | ✅ | |
| CrowdSec LAPI HTTP backend | CS_API_KEY usage | ❌ not ported | ❌ | Python only uses cscli; LAPI HTTP backend not in Python |

---

## Allowlist Sync

| Feature | Python function | Go location | Status | Notes |
|---|---|---|---|---|
| Read CrowdSec allowlist | `get_crowdsec_allowlist()` | `crowdsec.Client.ListAllowlist()` | ✅ | |
| Allowlist-aware ban filtering | `is_allowlisted()` | `app.allowlistSet.contains()` | ✅ | **IMPLEMENTED 2026-05-30** in both CF enforcement + CIDR paths; direct IP + CIDR coverage |
| AllowlistSyncApp daemon | _(Python: integrated in main loop)_ | `app.AllowlistSyncApp.Run()` | ⚠️ | Reads + logs CS allowlist; no CF write path yet |

---

## Cleanup Engine

| Feature | Python function | Go location | Status | Notes |
|---|---|---|---|---|
| Remove stale crowdsec-local-ban rules | `sync_cloudflare()` to_delete path | `app.CleanupApp.Run()` | ✅ | Deletes CF rules not in active ban set |
| ModSec cleanup (expired 2h rules) | `cleanup_modsec_cf_rules()` | ❌ not ported | ❌ | |
| CIDR ban expiry (24h) | `sync_cidr_bans()` expired loop | `cidrban.RealService` (expiry loop) | ✅ | |

---

## Recidivist Escalation

| Feature | Python function | Go location | Status | Notes |
|---|---|---|---|---|
| Track repeat offenders | `sync_recidivists()` | `recidive.RealService.Run()` | ✅ | Cursor-based deduplication; JSON state file |
| Escalate 2nd ban → 24h | `RECIDIV_ESCALATION = {1: "24h"}` | `recidive.escalationTable` | ✅ | |
| Escalate 3rd+ ban → 168h | `RECIDIV_DEFAULT = "168h"` | `recidive.escalationDefault` | ✅ | |
| Purge old entries (7-day window) | `purge_old_recidivists()` | `recidive.RealService` (window check) | ✅ | |
| Recidivist cursor (no double-count) | `recidivists["_cursor"]` | `recidive.RealService` (cursor field) | ✅ | |
| Wire into sync daemon | called in main loop | `app.CrowdSecSyncApp.Run()` | ✅ | Wired; requires BanSource injection |

---

## CIDR /24 Auto-Ban

| Feature | Python function | Go location | Status | Notes |
|---|---|---|---|---|
| Group bans by /24 | `sync_cidr_bans()` → `get_cidr24()` | `cidrban.toCIDR24()` | ✅ | IPv4 only (matches Python) |
| Threshold ≥ 2 distinct IPs | `CIDR_THRESHOLD = 2` | `cidrban.cidrThreshold` | ✅ | |
| Ban /24 in CF (ip_range target) | `add_cf_rule(cidr, target="ip_range")` | `cidrban.RealService` + `CFBanner` | ✅ | |
| Ban /24 in CrowdSec (cscli) | subprocess in `sync_cidr_bans()` | `cidrban.RealService` + `CSRangeBanner` | ✅ | |
| Expire /24 bans after 24h | expiry loop in `sync_cidr_bans()` | `cidrban.RealService` (expiry loop) | ✅ | |
| CIDR state persistence | `cidr-banned.json` | `cidrban.RealService.saveState()` | ✅ | |
| Wire into sync daemon | called in main loop | ❌ not wired in app.go | ❌ | cidrban.Service was removed from CrowdSecSyncApp struct |

---

## ModSecurity

| Feature | Python function | Go location | Status | Notes |
|---|---|---|---|---|
| Parse nginx error.log for ModSec events | `get_recent_modsec_events()` | `modsecurity.parseModSecEvents()` | ✅ | Regex match on `ModSecurity: Access denied` |
| Score threshold ≥ 5 | `MODSEC_SCORE_MIN = 5` | `modsecurity.modsecScoreMin` | ✅ | |
| 48h lookback | `LOOKBACK_HOURS = 48` | `modsecurity.lookbackHours` | ✅ | |
| Ban in CF (tag modsec-ban, 2h) | `add_cf_rule(ip, NOTE_TAG_MODSEC)` | `modsecurity.RealService` + `CFBanner` | ✅ | |
| State persistence (2h ban window) | `modsec-banned.json` | `modsecurity.RealService.saveState()` | ✅ | |
| Report to AbuseIPDB | `report_to_abuseipdb_raw()` in sync_modsec | ❌ not ported | ❌ | |
| Wire into sync daemon | called in main loop | `app.CrowdSecSyncApp.Run()` | ✅ | |

---

## AbuseIPDB Reporting

| Feature | Python function | Go location | Status | Notes |
|---|---|---|---|---|
| Report CrowdSec bans to AbuseIPDB | `sync_abuseipdb()` | `adapters/crowdsecevent` + `reporting` | ✅ | Reads decisions.log via crowdsecevent.LiveSource |
| Report OpenResty bouncer denials | `sync_bouncer_abuseipdb()` | `adapters/openrestyevent` + `reporting` | ✅ | |
| Report CloudFlare WAF events | `poll_cloudflare_waf()` → report | `adapters/cloudflareevent` + WAF replay | ✅ | Persistent cursor with 10-min overlap |
| Deduplication (7-day window) | `reported` dict keyed by ip:id | `storage/sqlite` outbox + dedup | ✅ | Go exceeds Python: SQLite-backed dedup |
| Retry failed reports | _(Python: inline, no retry)_ | `reporting.OutboxWorker` | ✅ | Go exceeds Python: persistent outbox with backoff |
| Category mapping (scenario→cats) | `SCENARIO_CATEGORIES` | `abuseformat.Format()` | ✅ | |
| Get nginx URIs for comment | `get_nginx_uris_for_ip()` | ❌ not ported | ❌ | |
| AbuseIPDB check for bouncer denials | `check_abuseipdb()` | `adapters/abuseipdb` | ✅ | |

---

## Cloudflare WAF Polling

| Feature | Python function | Go location | Status | Notes |
|---|---|---|---|---|
| GraphQL WAF event fetch | `fetch_cf_waf_events()` | `cloudflare.Client.ListWAFEventsSince()` | ✅ | |
| Threshold ≥ 3 hits / 300s window | `CF_WAF_THRESHOLD`, `CF_WAF_WINDOW_SECS` | `adapters/cloudflareevent` | ✅ | |
| Persistent cursor | `cf_waf_state.json` | SQLite cursor store | ✅ | Go exceeds Python: crash-safe SQLite |

---

## Lua / OpenResty State Sync

| Feature | Python function | Go location | Status | Notes |
|---|---|---|---|---|
| Push bans.json to /run/crowdsec-lua/ | `push_lua_state()` | ❌ not ported | ❌ | Python→Lua IPC; Go uses OpenResty HTTP source instead |
| Read events.jsonl from Lua | `read_lua_events()` | `openrestyevent.LiveSource` | ✅ | |
| Process honeypot/heuristic events | `process_lua_events()` | `openrestyevent.Service` | ⚠️ | Event types partially mapped |
| Lua auto-heal (stale version detect) | `_query_lua_status()` | ❌ not ported | ❌ | |

---

## Runtime / Daemon Infrastructure

| Feature | Python function | Go location | Status | Notes |
|---|---|---|---|---|
| Interval scheduler (60s) | `INTERVAL = 60` main loop | `scheduler.IntervalRunner` | ✅ | |
| Circuit breakers (CF, CS, AbuseIPDB) | `CircuitBreaker` class | `runtime/breaker` | ✅ | Go exceeds Python: persistent state |
| DRY_RUN / shadow mode | `DRY_RUN` env flag | `--dry-run` flag in cf-sync | ✅ | |
| Graceful shutdown (SIGTERM) | `_handle_signal()` | daemon signal handler | ✅ | |
| Health endpoint (/health) | `_start_health_server()` | `/healthz`, `/statusz` | ✅ | |
| Prometheus metrics (/metrics) | `_build_prometheus()` | `/metrics` + `observability/metrics` | ✅ | |
| SIGHUP hot reload | `_reload.set()` | ❌ not ported | ❌ | |
| sd_notify watchdog | `_sd_notify()` | ❌ not ported | ❌ | |
| BetterStack ingest | `send_to_betterstack()` | `betterstack.Client` + telemetry sinks | ✅ | |
| CF quota warning | quota check in `_fetch_cf_rules()` | ❌ not ported | ❌ | |
| Boot degraded mode | `_degraded_reason` | `runtime/health` | ⚠️ | Health model present; boot degraded logic not wired |
| Atomic JSON writes | `_atomic_write_json()` | state.JSONStore + recidive/cidrban save | ✅ | |
| WAL audit trail | `_wal_log()` | `runtime/journal` (JSONL) | ✅ | |

---

## Confidence Gate — Verified Inactive in Production

**Python function:** `_should_sync_to_cf()` / `CF_MIN_CONFIDENCE` env var  
**Go status:** ❌ Not ported  
**Production drift caused: ZERO**

Python logic (from config.py + main.py):
```python
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
CF_MIN_CONFIDENCE = os.environ.get("CF_MIN_CONFIDENCE", "low")  # default: "low"

def _should_sync_to_cf(scenario: str) -> bool:
    conf = _scenario_confidence(scenario)
    return _CONFIDENCE_RANK.get(conf, 1) >= _CONFIDENCE_RANK.get(CF_MIN_CONFIDENCE, 0)
```

When `CF_MIN_CONFIDENCE="low"` (rank=0): any scenario confidence (0, 1, or 2) >= 0 → **always True**.
Gate is effectively disabled; all scenarios sync to CF regardless of confidence level.

**Verified 2026-05-30:** Production `/etc/crowdsec/cf-sync.env` does NOT set `CF_MIN_CONFIDENCE`.
Python defaults to `"low"` → gate inactive. Go not implementing it causes **zero divergence**.

Gate becomes relevant ONLY if Python is configured with `CF_MIN_CONFIDENCE=medium` or `=high`.
If that config changes, implement `_scenario_confidence()` + confidence rank filter in `buildSyncPlan()`.

**Note:** Pre-2026-05-30 shadow reports may show `DriftConfidenceGate` counts — these were
misclassified because the drift classifier received `nil` for the allowlist parameter.
After the allowlist filter fix, correctly-labeled drift will appear only when allowlist
entries are present.

---

## ModSecurity / AppSec / Lua — Signal Classification

Three distinct security signal sources exist. They must not be conflated.

| Signal | Source | Python handler | Go handler | Status | Notes |
|---|---|---|---|---|---|
| Legacy ModSecurity | nginx error.log | `sync_modsec()` / `get_recent_modsec_events()` | `modsecurity.RealService` | ⚠️ Partial | CF ban wired; AbuseIPDB report missing |
| CrowdSec AppSec | CrowdSec decisions (AppSec component generates IPs) | via `get_active_bans()` | via `ListActiveBans()` | ✅ | AppSec decisions appear in cscli with origin="crowdsec"; handled transparently |
| Lua/OpenResty bouncer | `/run/crowdsec-lua/events.jsonl` | `sync_bouncer_abuseipdb()` / `read_lua_events()` | `openrestyevent.Service` | ✅ | Go reads events.jsonl and reports to AbuseIPDB |

**`modsecurity.RealService` is the LEGACY nginx log scanner** — it parses ModSecurity Access denied
lines from nginx error.log. This is distinct from CrowdSec's modern AppSec engine, which
produces standard CrowdSec decisions already handled by `ListActiveBans()`.

**CrowdSec AppSec**: Inferred to flow through standard CS decisions based on architecture.
Mark as "inferred" pending explicit verification of AppSec-generated decisions in `cscli decisions list` output.

---

## Summary (Updated 2026-05-30)

| Status | Count | Changes since 2026-05-29 |
|---|---|---|
| ✅ Implemented | 46 | +allowlist filter (CF + CIDR path), +anti-self-ban, +CIDR service wired |
| ⚠️ Partial | 4 | Allowlist write-path, ModSec AbuseIPDB, OpenResty events, boot degraded |
| ❌ Missing | 9 | Rule collapsing, confidence gate (inactive in prod), ModSec AbuseIPDB, nginx URI extraction, Lua state push, auto-heal, SIGHUP, sd_notify, CF quota warning |

---

## Remaining Gap List (ordered by operational risk)

1. **Rule collapsing** — Go adds individual /32s; Python collapses adjacent ranges — efficiency gap
2. **Confidence gate** — inactive in production (`CF_MIN_CONFIDENCE=low`); document before any config change
3. **ModSec AbuseIPDB reporting** — ModSec CF bans work; AbuseIPDB report missing
4. **SIGHUP reload** — operators must restart daemon to reload config
