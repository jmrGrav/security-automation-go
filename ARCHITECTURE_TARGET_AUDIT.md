# Architecture Target Audit

**Date:** 2026-05-30  
**Frame:** Intended final architecture — NOT Python parity.  
**Principle:** Go is the control-plane brain. External systems are producers or sinks.

---

## Architecture Model

```
External Signal Producers
  CrowdSec agent (decisions, AppSec)
  OpenResty/Lua (bouncer events, heuristics)
  Cloudflare WAF (edge block events)
         │
         ▼
  ┌──────────────────────────────┐
  │   Go Control-Plane (Brain)   │
  │                              │
  │  ingest → enrich → decide → │
  │  plan → execute → audit      │
  └──────────────────────────────┘
         │               │
         ▼               ▼
External Enforcement    Optional Sinks
  Cloudflare (edge)     AbuseIPDB (community intel)
  cscli (CS decisions)  BetterStack (telemetry)
                        [future: webhook, discord, slack]
```

---

## Subsystem Classification

### 1. CrowdSec Decisions

**Classification:** External Signal Producer + Enforcement Target

| | |
|---|---|
| **Source of truth** | CrowdSec SQLite DB (local) — authoritative |
| **Producer** | CrowdSec agent (local detections → scope=Ip, origin=crowdsec) + cscli (manual → origin=cscli) |
| **Consumer** | Go `ListActiveBans()` → `syncCloudflare()` → CF enforcement |
| **Execution path** | `cscli decisions list -o json` (15s timeout, 60s poll) → `FilterActiveBanIPs()` → `buildSyncPlan()` |
| **Current wiring** | ✅ **ACTIVE** — fully wired, shadow evidence confirms |
| **Notes** | CAPI decisions (community blocklist) are filtered out — handled only by iptables bouncer. This is correct: CAPI = iptables only, local detections = CF + cscli. |

---

### 2. CrowdSec AppSec

**Classification:** External Signal Producer

| | |
|---|---|
| **Source of truth** | CrowdSec AppSec engine (part of CrowdSec agent) |
| **Producer** | CrowdSec AppSec → decisions with `scope=Ip, origin=crowdsec` |
| **Consumer** | Same as CrowdSec decisions — `ListActiveBans()` picks up AppSec decisions transparently |
| **Execution path** | AppSec detection → CS decision created → cscli poll → Go sync → CF |
| **Current wiring** | ✅ **ACTIVE** — AppSec decisions are indistinguishable from other crowdsec-origin decisions |
| **Notes** | No special handling needed. AppSec decisions flow through the same path as all crowdsec-origin Ip-scope decisions. Verification: live decision `crowdsecurity/http-bad-user-agent` with `origin=crowdsec` is already picked up by Go. |

---

### 3. OpenResty/Lua

**Classification:** External Signal Producer

The Lua layer is NOT a decision engine from Go's perspective. It is a signal producer.

| | |
|---|---|
| **Source of truth** | OpenResty nginx + CrowdSec Lua bouncer |
| **Producer** | Lua writes two outputs: `bans.json` (enforcement cache) + `events.jsonl` (escalation signals) |
| **Consumer** | `openrestyevent.Service` reads `events.jsonl` → AbuseIPDB reporting + Go event ingestion |
| **Execution path** | Lua detects heuristic → writes event to `events.jsonl` → Go reads via atomic rename → `openrestyevent.Service.Process()` → `reporting.Service` |
| **Current wiring** | ⚠️ **PARTIALLY_ACTIVE** — wiring correct, `events.jsonl` absent (no current Lua escalations) |
| **Notes** | `bans.json` (Lua's nginx enforcement cache) is written by Python cf-sync's `push_lua_state()`. This is the gap: Go does not yet write `bans.json`. Until Go writes it, OpenResty's nginx-level enforcement uses a stale Python-generated list. CF-level enforcement continues correctly. The Turnstile/403 page: OpenResty sends this to clients; Go does not need to know about it — Go is informed by the resulting events in `events.jsonl`. |

---

### 4. Cloudflare Enforcement

**Classification:** External Enforcement Target

| | |
|---|---|
| **Source of truth** | Cloudflare API — canonical state for Go's plan diffing |
| **Producer** | Go `syncCloudflare()` — manages `crowdsec-local-ban` rules |
| **Consumer** | Cloudflare edge network |
| **Execution path** | `buildSyncPlan()` → `AddIPAccessRule()` / `DeleteIPAccessRule()` → CF REST API |
| **Current wiring** | ✅ **ACTIVE** (shadow mode: computes plan, no mutation) |
| **Activation** | Set `shadowMode=false` → live mutations begin |
| **Notes** | Anti-self-ban shield applied in `buildSyncPlan()`. Allowlist filter applied. Natural dedup via set arithmetic. Idempotent on restart/crash. The CF notifier (`crowdsec-notifier.service`) is a LEGACY ARTIFACT to be removed at cutover — it was extracted from Python cf-sync and was never the intended long-term path. |

---

### 5. AbuseIPDB Reporting

**Classification:** Optional Sink

| | |
|---|---|
| **Source of truth** | Go's reporting pipeline |
| **Producer** | Go: `crowdsecevent.Service` (CS local bans) + `openrestyevent.Service` (Lua events) + `cloudflareevent.Service` (WAF replay) |
| **Consumer** | AbuseIPDB API (community threat intelligence) |
| **Execution path** | Event → `reporting.Service.Process()` → dedup → SQLite outbox → `abuse.Executor.Execute()` → AbuseIPDB |
| **Current wiring** | ✅ **ACTIVE** in `cmd/crowdsec-sync` (crowdsecevent + openrestyevent); ⚠️ **PARTIALLY_ACTIVE** (WAF replay in cmd/cf-sync only) |
| **Notes** | The Python notifier's AbuseIPDB reporting (`/crowdsec/abuseipdb` route) should be DISABLED at cutover. The CrowdSec notification plugin (`notifications/abuseipdb.yaml`) that routes to the notifier should be removed. Go handles this now. The module should be toggleable: `enabled: true/false` based on `ABUSEIPDB_KEY` presence. |

---

### 6. BetterStack

**Classification:** Optional Sink

| | |
|---|---|
| **Source of truth** | Go security events |
| **Producer** | Go `telemetry/sinks.BetterStackSink` — receives `tmevents.SecurityEvent` |
| **Consumer** | BetterStack log ingestion API |
| **Execution path** | `reporting.Service.Observe()` → `sinks.MultiSink.Publish()` → `BetterStackSink.Publish()` → BetterStack API |
| **Current wiring** | ✅ **ACTIVE** when `BETTERSTACK_SOURCE_TOKEN` set |
| **Notes** | Activated by credential presence — correct behavior. The `crowdsec-poller.service` (decisions → decisions.log → Vector → BetterStack) is a separate telemetry path targeting the same sink. This is operational data (CS decisions log), not security events. Both can coexist. Future: all sinks (CF, AbuseIPDB, BetterStack, future webhooks) should be toggleable modules. |

---

### 7. Recidive

**Classification:** Core Control Plane

Recidive is a control-plane decision: "this IP has been seen N times — escalate the ban duration."

| | |
|---|---|
| **Source of truth** | Go's own ban history (decisions.log + own state file `recidivists.json`) |
| **Producer** | Multiple signal sources: CS decisions (via decisions.log), OpenResty/Lua events (future) |
| **Consumer** | `crowdsec.Client.AddIPDecision()` → cscli → extended ban |
| **Execution path** | `recidive.RealService.Run()` → `BanSource.ListRecentBans()` → cursor-based tracking → `Escalator.AddIPDecision()` |
| **Current wiring** | ❌ **DEAD_CODE** — `BanSource=nil`, `Escalator=nil` |
| **Gap:** | Must inject `BanSource` (adapter from decisions.log) and `Escalator` (`csClient`) |
| **Notes** | Signal sources for recidive: CS decisions (already in decisions.log) + OpenResty events (when available). The recidive logic itself is correct — only the injection is missing. This is a wiring gap, not a design gap. |

---

### 8. CIDR Aggregation

**Classification:** Core Control Plane

| | |
|---|---|
| **Source of truth** | Go's own recent ban history (decisions.log, 7-day lookback) |
| **Producer** | Multiple signal sources: CS decisions (via decisions.log), future: OpenResty events |
| **Consumer** | `cloudflare.Client.AddIPAccessRule()` (CF /24 rule) + `csClient.AddRangeDecision()` (cscli /24) |
| **Execution path** | `cidrban.RealService.Run()` → `cidrBanSourceAdapter.ListRecentBans()` → group by /24 → threshold=2 → CF + cscli |
| **Current wiring** | ✅ **ACTIVE** (live mode) — all dependencies injected |
| **Notes** | Shield and allowlist filters applied in `cidrBanSourceAdapter`. Correct behavior. The CIDR signals should eventually include OpenResty events (heuristics that reveal subnet-level attacks before individual bans accumulate). |

---

### 9. Cleanup

**Classification:** Core Control Plane

| | |
|---|---|
| **Source of truth** | Cloudflare API (canonical) vs cscli active decisions |
| **Producer** | Go `syncCloudflare()` `toDelete` path |
| **Consumer** | Cloudflare API (`DeleteIPAccessRule`) |
| **Execution path** | `buildSyncPlan()`: `toDelete = cfSet - banSet` → `DeleteIPAccessRule()` per stale rule |
| **Current wiring** | ✅ **ACTIVE** — same cycle as enforcement |
| **Notes** | Also `cmd/cf-cleanup` (standalone) does the same reconcile. The reconcile path in `syncCloudflare()` is the primary one. Python's `reconcile_state()` is fully replaced. |

---

### 10. Allowlist

**Classification:** Core Control Plane (filter gate)

The allowlist is not a feature — it is a negative enforcement gate.

| | |
|---|---|
| **Source of truth** | CrowdSec allowlist (`cscli allowlists inspect my_allowlist`) |
| **Producer** | `crowdsec.Client.ListAllowlist()` fetched per cycle |
| **Consumer** | `buildSyncPlan()` via `allowlistSet.contains()` — filters CF ban candidates |
| **Execution path** | Each cycle: `fetchAllowlist()` → `allowlistSet` (IP + CIDR matching) → applied in `buildSyncPlan()` and `cidrBanSourceAdapter` |
| **Current wiring** | ✅ **ACTIVE** — wired in both enforcement and CIDR paths |
| **Notes** | Fail-open on cscli error (matching Python's circuit-breaker). CIDR entries in allowlist are handled. Both paths (CF enforcement + CIDR /24) apply the filter. |

---

### 11. ModSecurity

**Classification:** Retired Component

| | |
|---|---|
| **Status** | **RETIRED** — ModSecurity not installed on this host |
| **Evidence** | `nginx not compiled with modsec`; `grep -c "ModSecurity" /var/log/nginx/error.log` = 0 |
| **Go code** | `modsecurity.RealService` exists but is DEAD_CODE (CFBanner=nil, 0 events) |
| **Action required** | Remove `modsec modsecurity.Service` field from `CrowdSecSyncApp`; remove the scheduler call; delete the package or mark clearly as tombstoned |
| **Notes** | This was a Python cf-sync feature. It was ported to Go as a placeholder but the underlying system feature was already removed. The SHADOW_DRIFT_ANALYSIS and PYTHON_FEATURE_MATRIX references to ModSec should be updated to RETIRED. |

---

## Alignment Matrix: Intended vs Current

| Subsystem | Intended Role | Current Go Status | Gap |
|---|---|---|---|
| CrowdSec decisions | Signal Producer → CF | ✅ Active | None |
| CrowdSec AppSec | Signal Producer → CF | ✅ Active (transparent) | None |
| OpenResty/Lua | Signal Producer → Go | ⚠️ Partially active (no events.jsonl) | Lua not emitting events currently |
| Cloudflare enforcement | Enforcement Target | ✅ Active (shadow) / ready (live) | Stop notifier at cutover |
| AbuseIPDB | Optional Sink | ✅ Active (crowdsecevent, openrestyevent) | WAF replay not in crowdsec-sync |
| BetterStack | Optional Sink | ✅ Active | None |
| Recidive | Core Control Plane | ❌ Dead code (BanSource nil) | Inject BanSource + Escalator |
| CIDR aggregation | Core Control Plane | ✅ Active (live mode) | None |
| Cleanup | Core Control Plane | ✅ Active | None |
| Allowlist | Filter gate | ✅ Active | None |
| ModSecurity | **RETIRED** | ❌ Dead code (CFBanner nil) | Remove from codebase |

---

## Gaps Between Intended Architecture and Current State

### Gap 1 — Recidive is dead code (HIGH)
`recidive.RealService` is instantiated and called every 60s cycle but executes zero logic because `BanSource=nil`. Recidive escalation — a core security policy — is not running.

**Fix:** Inject `BanSource` = adapter wrapping `csClient.ListRecentBans()` and `Escalator` = `csClient`.

### Gap 2 — WAF replay not in crowdsec-sync (MEDIUM)
`cloudflareevent.Service` (WAF replay) is wired only in `cmd/cf-sync --mode daemon`, not in `cmd/crowdsec-sync`. The primary running service (`crowdsec-sync-go`) cannot perform WAF replay.

**Fix:** Either port WAF replay into `cmd/crowdsec-sync` scheduler or deploy `cmd/cf-sync` daemon.

### Gap 3 — modsecurity.RealService not removed (LOW)
Dead code runs every 60s cycle (opens nginx error.log, finds 0 ModSec events, returns nil). Wastes a file open syscall. Creates audit noise.

**Fix:** Remove from `CrowdSecSyncApp` and mark package as retired.

### Gap 4 — OpenResty Lua bans.json (MEDIUM for full cutover)
Go does not write `/run/crowdsec-lua/bans.json`. OpenResty's nginx-level enforcement uses the Python-generated ban list. When Python cf-sync stops, the ban list stales.

**Fix:** Port `push_lua_state()` into Go. Input: `cidrban` state + `syncCloudflare()` plan. Output: `bans.json` atomic write.

### Gap 5 — Optional sinks not modular (FUTURE)
AbuseIPDB and BetterStack are activated by credential presence. The user's vision is explicit YAML/UI toggles per sink. Current implementation ties activation to env var presence — functional but not the intended UX.

**Fix:** Future — UI integration. Not a functional gap.

---

## Verdict

The Go control-plane architecture matches the intended design at the boundary level:
- Signal producers feed in correctly (CrowdSec, AppSec, OpenResty when active)
- Enforcement targets are correctly abstracted (CF, cscli)
- Optional sinks are correctly positioned (AbuseIPDB, BetterStack)

The gaps are wiring gaps, not design gaps:
- Recidive needs BanSource injection (wiring, not architecture)
- WAF replay needs a running binary (deployment, not architecture)
- ModSec needs removal (cleanup, not architecture)
- Lua bans.json needs porting (one function, not a new system)

The intended architecture is sound and partially implemented. The control-plane is ready for controlled authority with the gaps documented.
