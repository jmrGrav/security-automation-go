# Top 10 Problems — v1.6.x Audit

**Date:** 2026-06-12  
**Sources:** DATA_PIPELINE_AUDIT.md, AI_PROVIDERS_AUDIT.md, OPENRESTY_AUDIT.md, PROVIDERS_AUDIT.md  
**Ranking:** Critique > Important > Cosmétique

---

## Critique

### #1 — AI providers disabled despite keys being stored
**Audit:** AI_PROVIDERS_AUDIT · PROVIDERS_AUDIT  
All AI providers are disabled at runtime (`AI_PROVIDER_*_ENABLED` env vars not set → default `false`). Anthropic and Gemini keys are stored in the credential store but are never activated. The AI explain feature at `/intelligence` is non-functional. Model names are also empty (no env var, no UI path to set them).  
**Impact:** AI-assisted event analysis completely unavailable.  
**Root cause:** `ai.FromEnv()` reads enabled flag from env var; no runtime SQLite override for AI enabled/model.

---

### #2 — Confidence scoring gap silently suppresses real threats
**Audit:** DATA_PIPELINE_AUDIT  
`confidenceFromScore()` maps score 5–9 → confidence 0.65, just below the suppression threshold of 0.70. Events classified as `scanner` (known-bad UA: sqlmap, nikto, python-requests, curl/) get score +5 → confidence 0.65 → suppressed. This alone accounts for 1,704 scanner events not reported. Additionally, `exploit_attempt` events where a legit-crawler UA penalty drops score from 10 to 8 also get suppressed.  
**Impact:** 17% of events (1,868 records) are real security events that are never reported to AbuseIPDB and never acted upon.  
**Root cause:** `risk.go:265` — `confidenceFromScore(score 5-9) = 0.65` vs threshold `lowConfidence = 0.70`.

---

### #3 — OpenResty `events.jsonl` not written — entire event source dead
**Audit:** OPENRESTY_AUDIT  
`/run/crowdsec-lua/events.jsonl` does not exist. The Lua event-logging module is not installed in nginx. The OpenResty event ingestion pipeline (`processOpenResty()`) processes zero events every tick. All nginx-level WAF detections are enforced locally but never recorded or reported externally.  
**Impact:** One of three event sources completely inactive.  
**Root cause:** Lua event-logging script not loaded in nginx configuration.

---

## Important

### #4 — No unified provider management UI
**Audit:** PROVIDERS_AUDIT  
There is no page to add, edit, disable, or test providers. The `/providers` page is read-only. Adding an OpenAI key, rotating the AbuseIPDB key, or enabling Spamhaus requires direct SQLite manipulation or YAML/env var editing and a service restart. This is a significant operational gap.  
**Impact:** Operators cannot manage providers without shell access.

---

### #5 — CrowdSec events silently dropped when nginx log has no matching URI
**Audit:** DATA_PIPELINE_AUDIT  
`crowdsecevent.LiveSource.Read()` drops any ban event for which `lookupURIs()` finds no entries in the nginx access log. This affects any CrowdSec decision not triggered by HTTP (SSH brute force, raw TCP, non-HTTP bans from other bouncers). No evidence is written, no log message emitted.  
**Impact:** CrowdSec detections outside the HTTP layer are never correlated or reported.  
**Root cause:** `live.go:102` — `if len(uris) == 0 { continue }`.

---

### #6 — No Cloudflare bans visible in dashboard
**Audit:** DATA_PIPELINE_AUDIT  
Despite `mutations_enabled=true` and CrowdSec configured, no new IP access rules appear in Cloudflare. Either CrowdSec has no active bans (service not detecting attacks), or the orchestrator sync plan consistently shows `toAdd=0`. This requires operational investigation.  
**Impact:** CrowdSec detections not propagated to Cloudflare edge.

---

### #7 — Logout button missing from main operator console
**Identified in:** Previous session audit  
The main sidebar navigation (inline HTML in Go page handlers) has no logout button or link. The logout button exists only in the old wizard-style header (`views.templ`). Operators on a shared machine cannot easily terminate their session.  
**Impact:** UX/security — no visible session termination path.

---

### #8 — Dashboard "WAF events" badge misleads when events.jsonl missing
**Audit:** OPENRESTY_AUDIT  
The dashboard shows "OpenResty active (WAF events)" when `cfg.OpenResty.EventsFile != ""` AND the OpenResty detector says the service is running. It does NOT check whether the events file actually exists. The health page correctly shows YELLOW. The dashboard is wrong.  
**Impact:** Operator believes WAF events are being captured when they are not.  
**Root cause:** `server.go:946` — `openRestyDashboardDetail()` does not `os.Stat(eventsFile)`.

---

## Cosmétique

### #9 — Smoke test pre-flight DB probe shows WARNING despite passing
**Identified in:** Previous session  
`scripts/smoke-ui-runtime.sh` pre-flight check runs `grep -q '"error":null'` on the JSON output of `smoke-backend-status.sh`. The JSON is multi-line formatted; single-line grep fails, the pre-flight prints WARNING but the actual spec 09 tests pass correctly (they use the TypeScript `JSON.parse` path).  
**Impact:** Confusing output in smoke test runs. Spec tests still pass.

---

### #10 — Dashboard "reported=0" shows Prometheus session metric, not historical total
**Audit:** DATA_PIPELINE_AUDIT  
The WAF replay dashboard badge shows the Prometheus metric `cloudflare_events_reported_abuseipdb_total` which resets to 0 on service restart. The actual historical total (7 reports in scoped DB) is invisible from the dashboard. An operator watching the dashboard always sees "reported=0" even if 100 reports were sent yesterday.  
**Impact:** Operators cannot assess historical reporting effectiveness from the dashboard.

---

## Summary Table

| Rank | Severity | Title | Audit |
|------|----------|-------|-------|
| 1 | **Critique** | AI providers disabled despite keys stored | AI_PROVIDERS |
| 2 | **Critique** | Confidence gap suppresses scanners (17% of events) | DATA_PIPELINE |
| 3 | **Critique** | OpenResty events.jsonl not written | OPENRESTY |
| 4 | **Important** | No unified provider management UI | PROVIDERS |
| 5 | **Important** | CrowdSec events silently dropped without nginx URI | DATA_PIPELINE |
| 6 | **Important** | No Cloudflare bans despite mutations_enabled | DATA_PIPELINE |
| 7 | **Important** | No logout button in operator console | — |
| 8 | **Important** | Dashboard "WAF events" badge wrong when file missing | OPENRESTY |
| 9 | **Cosmétique** | Smoke pre-flight DB probe shows false WARNING | — |
| 10 | **Cosmétique** | Dashboard reported=0 hides historical totals | DATA_PIPELINE |
