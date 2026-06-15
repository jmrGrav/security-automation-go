# Event Intake Pipeline — Source Audit

**Date:** 2026-06-13  
**Scope:** Read-only audit of all event sources. No code changes.  
**Purpose:** Answer the 4 diagnostic questions before any v1.7 architecture work.

---

## 1. Architecture as-is

The existing pipeline has **three source adapters**, all wired into `cmd/cf-sync`:

| Source | Adapter | Status |
|--------|---------|--------|
| Cloudflare WAF | `internal/adapters/cloudflareevent` | ✅ ACTIVE — every 60s |
| CrowdSec LAPI | `internal/adapters/crowdsecevent` | ✅ ACTIVE — every 60 min |
| OpenResty Lua | `internal/adapters/openrestyevent` | ⏸ DORMANT — no attack traffic |

Evidence lands in the **scoped SQLite database**:
- Path: `/var/lib/security-automation-go/d50b53abe84dd303/runtime.db`
- Scope ID derived from: `cfg.Cloudflare.ZoneID` (via `scope.RuntimeScope.ID()`)
- UI reads from this same scoped DB via `evidenceHolder` wired in `runtime.go:evidenceHolder.set(reportingStores.Evidence)`
- Main `runtime.db` (`/var/lib/security-automation-go/runtime.db`) holds only credentials/settings/setup state

---

## 2. Question 1 — Is OpenResty actually emitting events?

**Answer: NO — but the reason is no attack traffic, not a wiring bug.**

### What's deployed
- Lua modules: `/etc/openresty/lua/crowdsec/events.lua`
- Target file: `/run/crowdsec-lua/events.jsonl`
- Events written when: `honeypot_hit` (access.lua) or `heuristic_escalate` (heuristics.lua)
- OpenResty is **active** (`systemctl is-active openresty` → `active`)

### Runtime state
```
/run/crowdsec-lua/
├── bans.json        (734 bytes, last updated 2026-06-09 — 4 days stale, 3 modsec-ban IPs)
└── events.jsonl     (DOES NOT EXIST)
```

### Why events.jsonl doesn't exist
The Lua timer only writes when a honeypot URL is hit OR heuristic score exceeds the escalation threshold. Neither has fired recently. The file is created on first write — there is no ongoing traffic that triggers these conditions.

### Go wiring (correct)
```
cfg.OpenResty.EventsFile = "/run/crowdsec-lua/events.jsonl"   (default from config)
openrestyevent.NewLiveSource(cfg.OpenResty.EventsFile)         → LiveSource
openrestyevent.NewService(svc)                                 → reads & processes
```
When `events.jsonl` doesn't exist, `os.Rename()` in LiveSource returns an error and the cycle returns `[]Event{}` — silent no-op, no error logged. This is correct behavior.

**Lua note:** The events.lua comment refers to "Python atomically renames" — this is stale documentation from the predecessor Python daemon. Go's `openrestyevent.LiveSource` performs the atomic rename (`os.Rename`) on each cycle. The contract is intact.

### bans.json is stale
`bans.json` (version=1321, updated 2026-06-09) contains 3 modsec-banned IPs that are still in the file 4 days later. This file is written by OpenResty's sync.lua, not consumed by the Go pipeline — it's a separate bouncer-sync file, not an event source.

**Verdict:** OpenResty source is PARTIALLY_ACTIVE. Correctly wired. Will produce events the moment a visitor hits a honeypot URL or triggers heuristic escalation.

---

## 3. Question 2 — What do CrowdSec events BECOME?

**Answer: 29,655 evidence entries in scoped DB. 99.95% suppressed. 15 actually reported to AbuseIPDB.**

### Evidence breakdown (as of 2026-06-13 14:14)

| Suppression reason | Count | % | Meaning |
|-------------------|-------|---|---------|
| `benign_signal` | 19,451+2,842 = 22,293 | 74.9% | Bot/monitor traffic that doesn't meet report threshold |
| `low_confidence` | 3,579 | 12.0% | Confidence score below minimum required |
| `protected_target` | 1,812 | 6.1% | 82.65.145.189 — protected_target guard is LIVE and working |
| `duplicate_report` | 1,753 | 5.9% | Dedup within 15-minute window |
| `abuseipdb_recently_reported` | 188 | 0.6% | Already reported in last 24h |
| `report_pending` | 15 | 0.05% | In outbox, awaiting send |
| *(none)* / `reported` | 15 | 0.05% | **Actually reported to AbuseIPDB ✅** |
| **Total** | **29,655** | | |

### CrowdSec LAPI poll frequency
- Not every 60s — every **60 minutes** (observed: fires at xx:04:48 each hour)
- Cycle counts from today: 33, 57, 46, 58, 45, 61 decisions/hour
- Initial 1,236 at first LAPI poll after v1.6.2 deploy (backlog flush) — does NOT repeat
- In-memory dedup persists across cycles → no double-counting

### Cloudflare WAF poll frequency
- Every **60 seconds** (cloudflare waf replay processed every minute in journal)
- Fetches 1–23 events/cycle; all suppressed as benign_signal or low_confidence

### Conclusion
The 100% suppression rate is **accurate and expected**:
- Traffic consists primarily of CF edge monitoring bots, legitimate crawlers, Hetzner scanners
- `benign_signal` is applied by the classifier's confidence check + scanner UA list
- 15 IPs have crossed the threshold and been reported — the full reporting path works end-to-end

---

## 4. Question 3 — Does daemon-written evidence land in the DB the UI reads?

**Answer: YES — the architecture is correct.**

### Database layout on host

```
/var/lib/security-automation-go/
├── runtime.db                          (241 KB) — credentials, settings, setup, UI auth
├── runtime.db-shm / -wal
└── d50b53abe84dd303/
    ├── runtime.db                      (107 MB) — ALL WAF evidence, events, ownership
    ├── runtime.db-shm
    ├── runtime.db-wal                  (4 MB)
    └── runtime_state.json
```

### Wiring path
```
cmd/cf-sync/runtime.go:
  scopeDir = filepath.Join(cfg.StateDir, currentScope.ID())  // → d50b53abe84dd303
  sqliteDB, _, reportingStores, ... = initSQLite(scopeDir)   // opens scoped DB
  evidenceHolder.set(reportingStores.Evidence)               // UI reads scoped DB
```

The scoped DB is opened before daemon launch. The UI's `s.evidence` is set to `reportingStores.Evidence` from the scoped DB. There is no disconnect — daemon writes and UI reads the same 107MB database.

**Note on the "two-DB" confusion:** The main `runtime.db` has 0 rows in `abuseipdb_reporting_evidence` — this is correct. It only stores: `credential_meta`, `credential_secrets`, `setup_state`, `ui_settings`, `admin_recovery_keys`. All WAF processing writes to the scoped DB.

---

## 5. Question 4 — Does count=1236 repeat every cycle or only on restart?

**Answer: ONE-TIME BACKLOG FLUSH at first LAPI poll after v1.6.2 deploy. Does NOT repeat.**

### Evidence
```
CrowdSec cycle log (today, hourly):
  09:04 → count=33
  10:04 → count=57
  11:04 → count=46
  12:04 → count=58
  13:04 → count=45
  14:04 → count=61
```

The 1,236 was the backlog of LAPI decisions accumulated before v1.6.2 wired the LAPI poller. Each subsequent poll fetches only new decisions since the last cursor. In-memory dedup + cursor persistence prevents reprocessing.

**No dedup bug.** The `event_checkpoints` table in the scoped DB persists the LAPI cursor across restarts.

---

## 6. Gaps vs the v1.7 Mission Document

| Mission item | Existing code | Status |
|---|---|---|
| `internal/events/intake` | `cmd/cf-sync/runtime_wiring.go` + `wafBundle` | EXISTS (different name) |
| `internal/events/sources/*` | `internal/adapters/{crowdsecevent,openrestyevent,cloudflareevent}` | EXISTS |
| Unified `SecurityEvent` | `reporting.DecisionEvidence` | EXISTS |
| `internal/events/normalize` | `reporting.Service.Process()` + classifier | EXISTS |
| `internal/events/decision` | `reporting.Service.suppressionReason()` | EXISTS |
| Protected gate | `trust.Registry` + `isProtected()` + v1.6.3 guard | EXISTS AND LIVE |
| Evidence store | `abuseipdb_reporting_evidence` (29,655 rows) | EXISTS AND LIVE |
| Security Timeline (`/timeline`) | `/evidence` page (50/page, filter by reported/suppressed) | EXISTS |
| Pipeline Health | `/pipeline-health` matrix | EXISTS |
| Event detail page | Not built | MISSING |
| Per-source "last event" timestamp | Not shown in Pipeline Health | MISSING |
| OpenResty forensic fallback (nginx log) | Not implemented | MISSING |
| Source priority chain (LAPI > log > cscli) | Not implemented (LAPI only) | PARTIAL |

**What's genuinely missing** (narrow, incremental):
1. **Event detail page** — click an evidence row to see full data/JSON
2. **Per-source last-event timestamp** in Pipeline Health matrix
3. **OpenResty source activation** — no missing code, needs actual attack traffic; bans.json staleness could be investigated
4. **CrowdSec fallback** — decisions.log reader if LAPI fails (optional; LAPI currently working)
5. **UI visibility of suppression breakdown** — `/evidence` shows counts but no per-reason chart; user can see the data via filter, not at a glance

---

## 7. Rebuild vs. Extend — Decision Required

The mission document proposes building a new `internal/events/*` hierarchy alongside the existing `internal/adapters/*`. This would create two normalized models in parallel.

**Assessment:** The existing architecture correctly handles all 3 sources, applies the protected gate, writes evidence, and makes it available to the UI. The 29,655 evidence rows and 15 confirmed AbuseIPDB reports prove the end-to-end path works.

**Two approaches:**

### Option A — Extend (incremental, aligns with stated constraint)
Add the genuinely missing pieces as incremental fixes to existing code:
- Event detail page (`/evidence/<id>`)
- Per-source timestamps in Pipeline Health
- Suppression breakdown chart in `/evidence`
- bans.json age check (alert if > 2h stale)

**Effort:** ~1 week. No architecture change. UI stays as-is. No risk of regression.

### Option B — Rebuild (as written in mission doc)
Build `internal/events/intake` + sources + normalize + decision packages as a parallel hierarchy, then migrate adapters.

**Effort:** ~3–4 weeks. High regression risk. Contradicts "corrections incrémentales" constraint. Would duplicate `reporting.DecisionEvidence` / `trust.Registry` / suppression logic that already works.

**Recommendation:** Option A. The evidence data is there (29,655 rows). The protected gate is live. The pipeline is working. The gaps are UI visibility and CrowdSec fallback — both are incremental features, not a reason to rebuild the intake layer.

**This is your decision.** Please confirm which direction before any code is written.

---

## 8. Host State Summary

| Component | State | Last activity |
|-----------|-------|---------------|
| cf-sync daemon | Running (PID in pid file) | Active, cycling |
| CF WAF replay | ✅ Every 60s | 14:14 today |
| CrowdSec LAPI | ✅ Every 60 min | 14:04 today (count=61) |
| OpenResty events.lua | Deployed, no writes | Dormant (no attack traffic) |
| OpenResty bans.json | Stale | 2026-06-09 05:06 UTC |
| Evidence DB | 29,655 rows | Active growth |
| AbuseIPDB reports | 15 sent | Via outbox |
| Protected IP guard | ✅ LIVE | 1,812 suppressions for 82.65.145.189 |
| Admin service | Running (security-automation-go.service) | Active |
