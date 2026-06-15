# Data Pipeline Audit — v1.6.x

**Date:** 2026-06-12  
**Scope:** All event ingestion and reporting paths: Cloudflare WAF, CrowdSec, OpenResty → AbuseIPDB + Cloudflare ban sync  
**Status legend:** ✅ OK · ⚠ PARTIAL · ❌ MISSING/BROKEN

---

## Executive Summary

Data IS flowing and being stored. The pipeline is not silent — it is actively suppressing events.
Key findings:

1. **Two separate SQLite databases exist.** The UI/smoke test probes `runtime.db` (credentials/settings). The daemon writes events to a scoped DB at `d50b53abe84dd303/runtime.db`. This discrepancy explains why `runtime.db` appeared empty.
2. **10,942 WAF events recorded** in the scoped DB since last service start. 7 IPs were reported to AbuseIPDB.
3. **77% of events suppressed as "benign_signal"** — classifier correctly identifies bootstrap probes, favicon hits, robots.txt fetches.
4. **17% suppressed as "low_confidence"** — a confidence scoring gap: risk score 5–9 maps to confidence 0.65, just below the 0.70 threshold. These events (scanners, medium-severity probes) are silently dropped even though they represent real malicious activity.
5. **OpenResty events: zero.** The Lua script does not write `events.jsonl` — only `bans.json` exists.
6. **CrowdSec events: silently dropped** if no nginx log URIs can be correlated.

---

## Architecture: Two SQLite Databases

```
/var/lib/security-automation-go/
├── runtime.db                        ← MAIN DB (UI, credentials, settings)
│   └── tables: ui_settings, credential_secrets, setup_state, schema_migrations
│
└── d50b53abe84dd303/                 ← SCOPED DB (daemon runtime)
    └── runtime.db                    ← Events, evidence, outbox, dedup, cursors
        └── tables: abuseipdb_reporting_evidence (10,942 rows)
                    abuseipdb_report_outbox (7 rows)
                    abuseipdb_report_dedup (7 rows)
                    runtime_cursors (1 row)
                    events (1 row)
```

The scope ID (`d50b53abe84dd303`) is derived at startup from `internal/runtime/scope`. The daemon, WAF replay poller, and outbox worker all use `scopeDir` (`cfg.StateDir/<scope_id>`). The UI setup wizard uses `cfg.StateDir` directly.

**Impact:** Any UI page that reads from `cfg.StateDir/runtime.db` will see 0 events. Only pages wired to `reportingStores.Evidence` (via the scoped DB) show real data.

---

## Pipeline 1: Cloudflare WAF → AbuseIPDB

### Flow Diagram

```
Cloudflare WAF API
    ↓ every 60s (cursor-based, 10min overlap window)
cloudflareevent.Service.ProcessSince()
    ↓ normalize raw event → classifier.Event
risk.Assess() → classification
    ↓
reporting.Service.Process()
    ├── suppressionReason() ?
    │   ├── isProtected(IP)           → "protected_target"
    │   ├── benign_bootstrap/probe    → "benign_signal"       ← 77%
    │   ├── confidence < 0.70         → "low_confidence"      ← 17%
    │   ├── no categories             → "no_abuse_categories"
    │   └── gate.isDuplicate()        → "duplicate_report"    ← 5%
    │
    ├── SUPPRESSED → recordEvidence() → scoped DB evidence table
    │
    └── PASS → abuseIPDB.Executor.Execute()
              → scoped DB outbox / dedup tables
              → AbuseIPDB API POST /api/v2/report
```

### Evidence Table Stats (scoped DB)

| suppression_reason        | count | %    |
|--------------------------|-------|------|
| benign_signal            | 8,439 | 77%  |
| low_confidence           | 1,868 | 17%  |
| duplicate_report         | 552   | 5%   |
| abuseipdb_recently_reported | 69 | 1%   |
| (none — reported)        | 7     | 0%   |
| report_pending           | 7     | 0%   |
| **Total**                | **10,942** | |

| abuse_type      | count |
|----------------|-------|
| benign_probe   | 8,062 |
| scanner        | 1,704 |
| exploit_attempt| 635   |
| benign_bootstrap| 377  |
| wordpress_probe| 164   |

### Status: ⚠ PARTIAL

**Working:**
- Fetch and classification: every event is classified correctly
- Cursor persistence: WAF since cursor saved to scoped DB, survives restarts
- Evidence recording: all decisions (suppressed and reported) written to scoped DB
- Outbox: 7 IPs reported to AbuseIPDB on 2026-06-11

**Root cause of mass suppression (low_confidence):**

`internal/security/risk/risk.go:259` — `confidenceFromScore()`:
```
score < 5   → confidence 0.25  (suppressed: SuppressedLowSignal)
score 5–9   → confidence 0.65  (suppressed: < 0.70 threshold)  ← GAP
score 10–19 → confidence 0.82  (passes)
score ≥ 20  → confidence 0.95  (passes)
```

Score 5–9 events include:
- Known scanner UA (+5): nikto, sqlmap, python-requests, curl — confidence 0.65, suppressed
- WordPress probes (+3): wp-login.php — confidence 0.25, suppressed
- Medium exploit attempts where a legit-crawler penalty (-2) drops score 10→8 → confidence 0.65

Events that PASS (score ≥ 10):
- Coraza/CRS/OWASP rule name in WAF event (+10)
- Sensitive extension URI (.env, .bak, .sql, .zip) (+10)
- Path traversal (+10)
- Exploit payload in URI (+10)
- High hit count ≥ 10 (+10)

**Implication:** Scanners like sqlmap and nikto hitting the site are NOT reported to AbuseIPDB because confidence 0.65 < 0.70.

---

## Pipeline 2: CrowdSec → AbuseIPDB

### Flow Diagram

```
CrowdSec decisions log (crowdsec.decisions_log)
    ↓ per interval tick
crowdsecevent.LiveSource.Read()
    ├── parse JSON decisions (event_type: alert/decision)
    ├── filter: action=banned, origin=crowdsec/cscli
    ├── filter: NOT cloudflare-waf scenario
    ├── lookupURIs(ip, maxURIs=5) ← scan nginx log for IP
    │   └── if len(uris) == 0: SILENT DROP ← ⚠ BUG
    └── emit RawEvent only if uris found

crowdsecevent.Service.Process() → reporting.Service.Process()
    └── same suppression chain as Cloudflare WAF
```

### Status: ⚠ PARTIAL

**Working:** decisions log is read and parsed.

**Silent drop bug** (`internal/adapters/crowdsecevent/live.go:102`):
```go
uris := s.lookupURIs(ip, 5)
if len(uris) == 0 {
    continue  // ← event silently dropped, no evidence written
}
```

If the nginx log does not contain recent requests from a banned IP (e.g., ban triggered by crowdsec-firewall-bouncer for SSH brute force, not HTTP), the event is dropped. No evidence, no report, no log message.

**Configuration:**
- `DecisionsLog`: configured (journal says log present)
- `NginxLogDir`: `/var/log/nginx`

---

## Pipeline 3: OpenResty → AbuseIPDB

### Flow Diagram

```
/run/crowdsec-lua/events.jsonl     ← FILE DOES NOT EXIST ❌
    ↓
openrestyevent.LiveSource.Read()
    └── os.Stat(EventsFile) → err: file not found → return nil, nil

wafRuntime.processOpenResty() → 0 events processed every tick
```

### Status: ❌ MISSING

**What exists in `/run/crowdsec-lua/`:**
```
bans.json   ← written by lua state push (pushLuaState), present ✅
events.jsonl ← MISSING ❌
```

**Root cause:** The `events.jsonl` file is written by a Lua script that must be added to the OpenResty/nginx configuration. The `bans.json` (ban list for the Lua bouncer) is written separately by `pushLuaState()`. The events file requires a separate Lua module to be loaded.

**Evidence in scoped DB:** 0 OpenResty events recorded.

---

## Pipeline 4: Cloudflare Ban Sync (CrowdSec → Cloudflare IP Rules)

### Flow Diagram

```
CrowdSec LAPI → cs.ListActiveBans()
    ↓
buildSyncPlan(): compare active bans vs CF IP access rules
    ├── toAdd: bans not yet in CF
    └── toDelete: CF rules no longer in bans
        ↓ (if !shadowMode)
cf.AddIPAccessRule() / cf.DeleteIPAccessRule()
    ↓
Cloudflare dashboard "IP Access Rules"
```

### Status: ⚠ PARTIAL

**Configuration:** mutations_enabled=true, cloudflare_mutations_enabled=true (ui_settings).

**Why no bans visible in Cloudflare:** One of:
1. CrowdSec has no active bans in LAPI (possible if crowdsec service is not detecting attacks)
2. The sync is running but the plan is `toAdd=0, toDelete=0`
3. Rate limiting or API errors in AddIPAccessRule

**Evidence:** The logs only show WAF replay messages; the "crowdsec sync tick" from the orchestrator may use a different log path. The orchestrator uses `pipeline.Orchestrator` not the legacy `CrowdSecSyncApp`, so the "crowdsec sync tick" message may not appear.

---

## Pipeline 5: Reporting Outbox (Retry Path)

### Status: ✅ OK

The `OutboxWorker` processes pending reports with retry logic. The 7 reports in the outbox all have status `reported` and `attempt_count=0`, meaning they were sent successfully on first attempt.

| IP | Source | Status | Sent |
|----|--------|--------|------|
| 2001:448a:... | cloudflare_waf | reported | 2026-06-11 07:59 |
| 88.151.32.194 | cloudflare_waf | reported | 2026-06-11 09:18 |
| 34.123.82.129 | cloudflare_waf | reported | 2026-06-11 10:07 |
| 160.250.123.42| cloudflare_waf | reported | 2026-06-11 12:21 |
| 2602:fb54:... | cloudflare_waf | reported | 2026-06-11 15:29 |
| 45.148.10.174 | cloudflare_waf | reported | 2026-06-11 15:35 |
| 2602:fb54:... | cloudflare_waf | reported | 2026-06-11 16:47 |

---

## Pipeline 6: UI Display Layer

### Status: ⚠ PARTIAL

The forensics, audit, and intelligence pages are served by the UI server. Their data comes from the scoped DB via `reportingStores.Evidence`. Pages that are wired to this store should display the 10,942 recorded events.

**What IS displayed:** depends on whether UI handlers use the evidence store passed via `reportingStores.Evidence` at line 339 of `runtime.go`.

**What the Dashboard shows:** WAF replay counts (reported/suppressed) from Prometheus metrics, not from SQLite queries. The dashboard "reported=0" badge shows the current-session metric, not the historical database.

**Smoke test DB probe** (`smoke-backend-status.sh`): probes the MAIN DB (`runtime.db`) which is correct for credential presence checks. It cannot see the scoped DB's event counts.

---

## Summary Table

| Pipeline | Source | Ingestion | SQLite (scoped) | AbuseIPDB |
|----------|--------|-----------|-----------------|-----------|
| Cloudflare WAF | ✅ API polled | ✅ Classified | ✅ 10,942 rows | ⚠ 7 reported (17% low_conf suppressed) |
| CrowdSec | ✅ Log present | ⚠ Silent drop if no nginx URI | ❓ Unknown | ❓ Unknown |
| OpenResty | ❌ events.jsonl missing | ❌ 0 events read | ❌ 0 rows | ❌ |
| CF Ban Sync | ✅ LAPI configured | ✅ Every 60s | N/A | N/A — 0 new CF bans |
| Outbox retry | ✅ | ✅ | ✅ 7 sent | ✅ 7 confirmed |

---

## Problems Identified

| # | Severity | Problem |
|---|----------|---------|
| P1 | **Critique** | Confidence gap: score 5–9 → confidence 0.65 < 0.70 threshold. Scanners (nikto, sqlmap, curl) never reported. |
| P2 | **Critique** | OpenResty `events.jsonl` not written — entire OpenResty event source is dead. |
| P3 | **Important** | CrowdSec events silently dropped when nginx log has no URI for banned IP. |
| P4 | **Important** | Two SQLite databases (main vs scoped) — UI forensics pages may be reading from wrong DB. |
| P5 | **Important** | No Cloudflare bans visible — CrowdSec ban → CF sync may not be producing any adds. |
| P6 | **Cosmétique** | Dashboard "reported=0" shows Prometheus metric (current-session), not historical total. |
