# Cutover Execution Report — security-automation-go v1.2.0

**Date:** 2026-06-06  
**Operator:** Automated cutover procedure  
**Target:** Promote Go daemon from shadow authority to sole CF sync authority  
**Status:** ⛔ BLOCKED — CF API token invalidated; Phase 3 prerequisite unmet

---

## Phase 1 — Pre-Cutover State Assessment

### Backups

| Artifact | Source | Destination | Status |
|---|---|---|---|
| cf-sync state | `/var/lib/cf-sync` | `/var/backups/cf-sync-pre-cutover-2026-06-06` | ✅ DONE |
| security-automation-go config | `/etc/security-automation-go` | `/var/backups/security-automation-go-pre-cutover-2026-06-06` | ✅ DONE |

### Service Status at Cutover Start

**Go daemon (`cf-sync.service`)**
- Status: `active (running)` — PID 2750484, started 2026-06-05T23:04:11+02:00, uptime ≈16h at assessment
- Binary: v1.0.0 (pre-v1.2; installed at `/usr/local/bin/cf-sync`)
- Mode: shadow (`service_name=cf-shadow`), `dry-run=true` (default, not overridden), no mutations
- Config: `/etc/security-automation-go/cf-shadow.yaml` — no `mutations_enabled`
- Metrics: `127.0.0.1:9091` — `/healthz` → OK, `/readyz` → READY, `/statusz` → healthy
- statusz: `{"version":"v1.0.0","health":{"status":"healthy"},"breaker":{"state":"closed"},"lock":{"is_locked":false},"reconciliation":{"drift_detected":false},"quarantine":{"active_items":0}}`

**Python daemon (`crowdsec-cf-sync.service`)**
- Status: `active (running)` — uptime ≈8 days at assessment
- CF sync: **DEGRADED** — Cloudflare circuit breaker OPEN since 2026-06-06T12:01 (3h+ before assessment)
- Cause: `CF HTTP 401: {"code":10000,"message":"Authentication error"}` on all CF read attempts
- Effect: CrowdSec → Cloudflare sync has been non-functional since 12:01 today; CF firewall rules are frozen

### Shadow Validation Summary

| Metric | Value | Threshold | Status |
|---|---|---|---|
| Total cycles | 10,081+ (file: 10,566 lines) | — | — |
| 7-day agreement | 99.98% | ≥99.9% | ✅ PASS |
| All-time average | 99.98% | ≥99.9% | ✅ PASS |
| Max consecutive in-sync | 5,680 cycles | — | — |
| False positives (algorithmic) | 0 | 0 | ✅ PASS |
| False negatives (algorithmic) | 0 | 0 | ✅ PASS |
| Timing transients | 2 IPs | Expected | ✅ ACCEPTABLE |

Shadow validation window: **COMPLETE** (7-day baseline elapsed at ~04:47 UTC 2026-06-06). Shadow cycle writing stopped after completion — expected behavior. Daemon continues running cycles in dry-run mode.

### CF API Token Status

| Service | Token Source | Status | Detail |
|---|---|---|---|
| Go shadow | `/etc/security-automation-go/cf-shadow.env` `CF_API_TOKEN` | ⚠️ PARTIAL | Reads (list rules) work; `cloudflare.discovery.VerifyToken` → HTTP 401 code 1000 "Invalid API Token" |
| Python production | `/etc/crowdsec/cf-sync.env` `CF_API_TOKEN` | ❌ FAILED | All CF reads → HTTP 401 code 10000 "Authentication error" since 2026-06-06T12:01 |

**Assessment:** Python's production CF token was revoked or expired at approximately 12:01 today. Go's shadow token can still read CF rules (list endpoint) but fails on the `VerifyToken` endpoint — likely a scope limitation or a different token lifecycle. Go's shadow token has **not been verified** for write access (mutation scope).

---

## Phase 2 — Go Authority Mode Verification

**Gate result: FAIL**

| Check | Required | Observed | Status |
|---|---|---|---|
| `dry-run=false` | Explicit `-dry-run=false` flag | Default `true`, not overridden | ❌ FAIL |
| CF mutations enabled | `mutations_enabled: true` in config | Not in `cf-shadow.yaml` | ❌ FAIL |
| CF write token available | Write-capable CF API token | Shadow token write scope unverified | ⚠️ UNKNOWN |
| `healthz` | OK | OK | ✅ PASS |
| `readyz` | READY | READY | ✅ PASS |
| SQLite healthy | Healthy | Healthy (from statusz) | ✅ PASS |
| Replay engine healthy | Healthy | Healthy (from statusz) | ✅ PASS |
| Circuit breaker | Closed | Closed | ✅ PASS |
| Drift detected | None | None | ✅ PASS |

**Phase 2 verdict: BLOCKED — cannot proceed to Phase 3.**

---

## Phase 3 — Controlled Promotion

**Status: NOT EXECUTED** — blocked pending Phase 2 resolution.

---

## Phase 4 — Live Monitoring Window

**Status: NOT EXECUTED** — blocked.

---

## Phase 5 — Functional Validation

**Status: NOT EXECUTED** — blocked.

---

## Phase 6 — Rollback Plan

If Phase 3 proceeds and Go is found to be non-functional:

1. Immediately restart Python: `sudo systemctl start crowdsec-cf-sync && sudo systemctl enable crowdsec-cf-sync`
2. Restore Go to shadow mode: revert service ExecStart to shadow config and remove `-dry-run=false`
3. Validate Python is syncing (check journald for successful CF cycle)
4. Root-cause the Go failure before re-attempting cutover

State backup available at `/var/backups/cf-sync-pre-cutover-2026-06-06/` if SQLite restore is needed.

---

## Phase 7 — Production Acceptance

**Status: NOT EXECUTED** — blocked.

---

## Blockers — Required Actions Before Phase 3

### Blocker 1 (HARD): CF API Token with Write Permissions

The Cloudflare API token currently in use by the Go shadow service does not have confirmed write access. Python's production token has been invalid since 12:01 today.

**Required action:** Generate a new Cloudflare API token with:
- Permission: `Zone / Firewall Services / Edit`
- Zone: `d2f7807c2c5b7c9737da45f538072423` (arleo.eu)
- Store in a secret file (e.g., `/etc/security-automation-go/cf-api-token`) with mode `0600`
- Update service to load: `CF_API_TOKEN_FILE=/etc/security-automation-go/cf-api-token`

Alternatively: confirm whether the existing shadow token (`CF_API_TOKEN` in `cf-shadow.env`) has write scope — if it does, it can be reused once the `VerifyToken` 401 is explained.

### Blocker 2: v1.2 Binary Installation

A v1.2 binary was built successfully from the current repository:
```
/tmp/cf-sync-v1.2  (38 MB, built 2026-06-06T15:23)
```

Install command:
```bash
sudo systemctl stop cf-sync
sudo install -m 755 /tmp/cf-sync-v1.2 /usr/local/bin/cf-sync
```

### Blocker 3: Production Config

Create `/etc/security-automation-go/cf-daemon.yaml` with mutations enabled:
```yaml
version: v1
global:
  service_name: cf-daemon
  log:
    level: info
    format: json
cloudflare:
  zone_id: d2f7807c2c5b7c9737da45f538072423
  mutations_enabled: true
crowdsec:
  decisions_log: /var/log/crowdsec/decisions.log
  nginx_log_dir: /var/log/nginx
  bin_path: cscli
  timeout: 15s
  allowlist_name: my_allowlist
interval: 60s
state_dir: /var/lib/cf-sync
```

### Blocker 4: Service Unit Update

Update `/etc/systemd/system/cf-sync.service` ExecStart:
```ini
ExecStart=/usr/local/bin/cf-sync -mode daemon -config /etc/security-automation-go/cf-daemon.yaml -metrics-addr 127.0.0.1:9091 -dry-run=false
```

Also fix: move `StartLimitIntervalSec=300` from `[Service]` to `[Unit]` section to eliminate systemd warning.

---

## Operational Summary

| Phase | Status | Evidence |
|---|---|---|
| Phase 1 — State assessment | ✅ COMPLETE | Both services documented; backups taken |
| Phase 2 — Authority verification | ❌ BLOCKED | dry-run=true; no mutations config; CF write token unverified |
| Phase 3 — Stop Python, restart Go | ⏸️ NOT STARTED | Awaiting Blocker 1 and 2 resolution |
| Phase 4 — Monitoring window | ⏸️ NOT STARTED | — |
| Phase 5 — Functional validation | ⏸️ NOT STARTED | — |
| Phase 6 — Rollback plan | ✅ DOCUMENTED | Backup at `/var/backups/cf-sync-pre-cutover-2026-06-06/` |
| Phase 7 — Production acceptance | ⏸️ NOT STARTED | — |

---

## Urgency Assessment

**Python's CF sync has been broken since 12:01 today (3h+ before this report).** CF firewall rules are frozen — new CrowdSec bans are not being pushed to Cloudflare and expired bans are not being removed.

This makes the cutover **urgent** but does not change the prerequisites. Go cannot take over until it has a write-capable CF token and production config. The cutover does not introduce new risk — the existing production authority is already non-functional.

**Recommended next action:** Rotate the Cloudflare API token via the Cloudflare dashboard, create the production config, and re-execute Phase 3.

---

*Report generated: 2026-06-06. Binary built: /tmp/cf-sync-v1.2 (38 MB). Backups: /var/backups/cf-sync-pre-cutover-2026-06-06/.*
