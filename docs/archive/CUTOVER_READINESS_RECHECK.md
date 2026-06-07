# Cutover Readiness Recheck

**Date**: 2026-06-06  
**Auditor**: automated read-only recheck (Phase 5 gate)  
**Scope**: cf-sync service — shadow → live cutover go/no-go  

---

## 1. Executive Summary

The CF API token rotation has **not yet taken effect** for the running service. All three env files that could supply a valid CF_API_TOKEN were tested; every one returns HTTP 401 from Cloudflare's VerifyToken endpoint. The running service (PID 2750484, v1.1.2-dirty, dry-run=true) is cycling every 15 minutes and emitting `"quota refresh failed … HTTP 401 Invalid API Token"` in the journal. The newly-built binary at `/tmp/cf-sync-v1.2` (module version `v1.1.2-0.20260606130653-3a035fe342a8`, clean build) is ready but not yet installed. A production config (`mutations_enabled: true`, `dry_run: false`) does not exist — only the shadow config is present. Service auto-start is disabled. **Cutover is NOT ready.** Three hard blockers must be resolved before the cutover checklist can be re-run: (1) deploy the rotated token into the env file the service reads, (2) create a production config with mutations enabled and dry-run off, and (3) install and enable the v1.2 binary.

---

## 2. CF Token Status

**Status: INVALID — rotated but not yet deployed to the loaded env file**

| File | Var Name | Mtime | VerifyToken |
|---|---|---|---|
| `/etc/security-automation-go/cf-shadow.env` | `CF_API_TOKEN` | 2026-05-29 22:39 | HTTP 401 |
| `/etc/security-automation/secrets/cf_sync_api_token.env` | `CF_SYNC_API_TOKEN` | 2026-06-05 17:50 | HTTP 401 |
| `/etc/crowdsec/cf-sync.env` | `CF_API_TOKEN` | 2026-05-24 03:04 | HTTP 401 |

Key observations:
- The service unit loads env files in order: `cf-shadow.env` then `cf_sync_api_token.env`. The binary uses the env var `CF_API_TOKEN` (confirmed from binary strings). The secrets file only exports `CF_SYNC_API_TOKEN`, so it does not override the revoked token in `cf-shadow.env`.
- The `cf_sync_api_token.env` file was modified 2026-06-05 17:50 (after the 12:01 revocation), but it uses the wrong variable name (`CF_SYNC_API_TOKEN`) and is also returning 401 in any case.
- Journal confirms continuous 401 failures every 15 minutes from the live PID (last seen: 2026-06-06T16:04).
- The new token has NOT been written to any env file that the service can consume.

---

## 3. Production Config Status

**Status: MISSING — only shadow config exists**

```
/etc/security-automation-go/
  cf-shadow.yaml   (shadow config — dry-run inferred, no mutations_enabled key)
  cf-shadow.env    (revoked token)
```

No file named `cf-sync.yaml`, `cf-live.yaml`, or `cf-production.yaml` exists anywhere under `/etc`. The shadow config does not contain `mutations_enabled` (confirmed: `grep -r mutations_enabled` returned no output). A production config with `mutations_enabled: true` must be created before cutover.

---

## 4. Service Configuration Gaps

| Parameter | Current State | Required for Cutover |
|---|---|---|
| `dry_run` | `true` (startup log: `dry_run=true`) | `false` |
| `mutations_enabled` | absent from config | `true` |
| Binary version installed | v1.1.2-dirty (installed 2026-06-05 23:04) | v1.2 clean build |
| Service enabled | `disabled` | `enabled` |
| ExecStart | `-mode daemon -config /etc/security-automation-go/cf-shadow.yaml -metrics-addr 127.0.0.1:9091` | production config path, no dry-run flag |

The startup log (`/var/log/security-automation/startup.log`) recorded at 2026-06-05T21:04:11Z shows `dry_run=true providers=[]`. The current PID (2750484) started at 2026-06-05T23:04:11Z with identical flags.

One additional warning present at every start: `"failed to load default rego policy" error="open internal/policy/rego/admission.rego: no such file or directory"`. This is non-fatal for shadow mode but should be investigated before live operation.

---

## 5. Health Check Results

| Endpoint | Result |
|---|---|
| `GET /healthz` | `OK` |
| `GET /readyz` | `READY` |
| `GET /statusz` | See below |
| `/metrics` | No output (metrics endpoint returned nothing) |

Full statusz:
```json
{
  "version": "v1.0.0",
  "started_at": "2026-06-05T23:04:11.513744043+02:00",
  "uptime": "17h5m53s",
  "health": {"status": "healthy", "consecutive_fails": 0},
  "breaker": {"state": "closed", "failure_count": 0, "threshold": 0},
  "lock": {"is_locked": false},
  "reconciliation": {"drift_detected": false},
  "quarantine": {"active_items": 0}
}
```

Note: statusz reports version `v1.0.0` but the binary embeds module version `v1.1.2-dirty`. This is a version-string mismatch (the version field in statusz reflects a hardcoded constant that was not updated at build time).

### SQLite Health

```
Database:  /var/lib/cf-sync/7b8e9c6629df53f0/runtime.db  (204 KB)
PRAGMA integrity_check: ok
PRAGMA journal_mode: wal
WAL file: 0 bytes (checkpointed clean)
Tables: 15 (all present)
Rows in runtime_cursors: 0
Rows in events: 0
```

SQLite is structurally healthy. Zero rows in `runtime_cursors` and `events` is expected for a shadow-only daemon that has never executed a live mutation.

---

## 6. Startup Log Summary

From `/var/log/security-automation/startup.log` (written 2026-06-05T21:04:11Z, service current PID started 23:04:11Z):

```
2026-06-05T21:04:11Z startup version= mode=daemon bind= config=/etc/security-automation-go/cf-shadow.yaml db=/var/lib/cf-sync dry_run=true providers=[]
```

- `version=` is empty (build-time version injection not wired).
- `providers=[]` confirms no live provider quota was successfully initialized (consistent with 401 on startup).
- The rego policy warning (`admission.rego: no such file or directory`) appeared at every service start.
- `runtime_state.json` shows lifecycle status `"discovering"` since 2026-06-05T15:52:55Z — the daemon has never completed a discovery cycle due to the invalid token.

---

## 7. Readiness Gate Table

| Gate | Required | Observed | Status |
|---|---|---|---|
| CF token valid | HTTP 200 on VerifyToken | HTTP 401 (all env files) | FAIL |
| CF read permission | HTTP 200 on list rules | Not tested (token invalid) | FAIL |
| CF write permission | HTTP 200 on rulesets | Not tested (token invalid) | FAIL |
| dry-run=false | Explicit flag or config | dry_run=true (startup log) | FAIL |
| mutations_enabled | true in config | absent from cf-shadow.yaml | FAIL |
| Production config | Exists at /etc/security-automation-go/ | Missing (shadow config only) | FAIL |
| v1.2 binary ready | Built and installed | Built at /tmp/cf-sync-v1.2 (not installed) | PARTIAL |
| healthz | OK | OK | PASS |
| readyz | READY | READY | PASS |
| SQLite healthy | PRAGMA integrity_check: ok | ok, WAL clean | PASS |
| Service enabled | enabled | disabled | FAIL |

Shadow validation (informational, not a cutover gate):
- 10,566 shadow cycles recorded in `shadow-cycles.jsonl`
- Last cycle: 2026-06-06T04:47:57Z — `agreement_pct: 100`, `in_sync: true`
- Shadow validation window: COMPLETE

---

## 8. Blockers

### CRITICAL

1. **CF_API_TOKEN invalid in all deployed env files** — The revoked token is still what the running service reads. The new token (stated to have been rotated) has not been written to `/etc/security-automation-go/cf-shadow.env` (or any env file that exports `CF_API_TOKEN`). Additionally, `/etc/security-automation/secrets/cf_sync_api_token.env` exports `CF_SYNC_API_TOKEN` (wrong variable name) and is also returning 401. Until a valid token is deployed, no CF API call will succeed and cutover cannot proceed.

2. **Production config does not exist** — `/etc/security-automation-go/cf-shadow.yaml` is the only config. A production config with `mutations_enabled: true` must be created. Without it, even if the binary is switched to v1.2, it will continue in shadow/read-only mode.

3. **dry_run=true is active** — The ExecStart line does not pass `-dry-run=false` and the config does not disable dry-run. All reconciliation cycles are no-ops. Switching to live operation requires either an explicit flag in ExecStart or a config field.

### HIGH

4. **v1.2 binary not installed** — `/tmp/cf-sync-v1.2` (clean build, `v1.1.2-0.20260606130653-3a035fe342a8`, built 2026-06-06 15:23) exists but `/usr/local/bin/cf-sync` still contains the dirty build from 2026-06-05 23:04. The binary must be installed (and the service reloaded) before cutover.

5. **Service is disabled** — `systemctl is-enabled cf-sync` returns `disabled`. After cutover, a reboot would leave the system unprotected. The unit must be enabled before or during the cutover window.

### MEDIUM

6. **Rego admission policy missing** — `internal/policy/rego/admission.rego` is not present on disk. The binary logs a WARN at every start. For shadow mode this is non-fatal; for live operation with governance/approval workflows it may block rule admission.

7. **statusz version mismatch** — Reports `"version":"v1.0.0"` but binary is `v1.1.2-dirty`. The version constant was not updated. This makes incident triage harder. Should be corrected in the v1.2 build (verify after install).

8. **CF_SYNC_API_TOKEN variable name in secrets file** — The file `/etc/security-automation/secrets/cf_sync_api_token.env` exports `CF_SYNC_API_TOKEN` but the binary reads `CF_API_TOKEN`. If the intent was for this file to carry the rotated token, the variable name must be corrected (or the service unit must map it).

### LOW

9. **AbuseIPDB API key also 401** — `crowdsec-cf-sync` (Python service, enabled, Cycle 11882 OK on Python side) is also hitting HTTP 401 on CF API calls, confirming the token problem is global. AbuseIPDB key is separately revoked per startup log. These are independent of the Go cutover but should be resolved in parallel.

10. **crowdsec-cf-sync Python service** — Still running and enabled (`crowdsec-cf-sync` is `enabled`), raising CF 401 errors every cycle. Once the Go service cuts over, the Python service should be disabled to avoid conflicting writes.

---

## 9. Final Phase 5 Verdict

**NOT READY FOR CUTOVER**

Six gates are failing. The hard stop is the CF API token: the running service has been emitting HTTP 401 every 15 minutes since the revocation on 2026-06-06T12:01, and the stated rotation has not reached the env file that the binary reads. No CF operation — shadow or live — is succeeding. All other cutover prerequisites (production config, dry-run=false, v1.2 install, service enable) are also unmet.

**Minimum steps before re-running this checklist:**

1. Write the new CF API token into `/etc/security-automation-go/cf-shadow.env` as `CF_API_TOKEN=<new-token>` (root-only, mode 0600).
2. Run `systemctl restart cf-sync` and verify the next journal cycle shows no 401.
3. Re-run VerifyToken check (this document's Check 1) to confirm HTTP 200, read 200, and write-scope 200.
4. Create `/etc/security-automation-go/cf-sync.yaml` (production config) with `mutations_enabled: true` and without dry_run.
5. Install `/tmp/cf-sync-v1.2` to `/usr/local/bin/cf-sync` and update ExecStart if needed.
6. `systemctl enable cf-sync`.
7. Re-run this full checklist.
