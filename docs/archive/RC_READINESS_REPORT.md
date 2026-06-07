# RC Readiness Report — v1.2.0-rc1

**Date:** 2026-06-06
**Branch:** main

---

## 1. Working Tree Status

| Check | Result |
|---|---|
| Uncommitted changes | CLEAN |
| Commits pushed to origin | NO — 8 commits ahead of origin/main |

> Note: origin/main is a local bare remote (offline development). Commits are staged for push when connectivity is established.

## 2. Local Validation Gates

| Gate | Result |
|---|---|
| `gofmt -l .` | CLEAN — no files reported |
| `go vet ./...` | CLEAN — exit 0, no issues |
| `go build ./...` | PASS — exit 0 |
| `go test ./...` | PASS — 109 packages pass, 0 failures |
| `go test -race ./...` | PASS — no DATA RACE detected |

## 3. Skipped Tests

| File | Line | Reason |
|---|---|---|
| `internal/openresty/state/writer_test.go` | 196 | Running as root — permission checks don't apply |
| `internal/storage/sqlite/db_test.go` | 184 | Root bypasses file permissions |
| `internal/cloudflare/transport/transport_test.go` | 78 | `transport` hardcodes `BaseURL` as const; covered via `ExecuteAndDecode` tests below |

All three skips are conditional or narrowly scoped. None represent unverified logic paths in normal execution.

## 4. Open TODO Items

| Task | Description | Status |
|---|---|---|
| Task 1 | Admin token remediation | ✅ Resolved (v1.1.1 + v1.2) |
| Task 2 | CSRF remediation | ✅ Resolved (v1.1.1) |
| Task 3 | SQLite hardening | ✅ Resolved (v1.1.1) |
| Task 4 | CrowdSec validation hardening | ✅ Resolved (v1.1.1) |
| Task 5 | Rollback planner correctness | ✅ Resolved (v1.1.1) |
| Task 6 | Low findings | ✅ Resolved (v1.1.1) |

## 5. Pre-Sprint Audit Findings Disposition

| ID | Severity | Finding | Status |
|---|---|---|---|
| SEC-01 | MEDIUM | CF_SYNC_API_TOKEN env-only | ✅ RESOLVED — CF_SYNC_API_TOKEN_FILE added (v1.2) |
| SEC-02 | MEDIUM | Localhost-only UI assumption | ACCEPTED — UI defaults to 127.0.0.1:6969, documented |
| SEC-03 | LOW | CSRF on some routes | ✅ RESOLVED — all 10 POST handlers protected (v1.1.1) |
| OPS-01 | HIGH | DynamicUser vs log perms | ✅ RESOLVED — LogsDirectory=security-automation in unit (v1.1.1+) |
| OPS-02 | HIGH | Missing SIGUSR1 handler | ✅ RESOLVED — copytruncate logrotate strategy (v1.2) |
| OPS-03 | MEDIUM | Startup log lifecycle | ✅ RESOLVED — internal/startuplog package operational (v1.2) |

## 6. Pre-Existing Known Gaps (Out of Scope for v1.2)

- `internal/cloudflare/transport`: no unit tests (requires live Cloudflare token)
- `internal/crowdsec/adapter`: no unit tests (requires live cscli binary)
- ModSecurity CF ban: not yet ported — Python `crowdsec-cf-sync` continues
- Recidive escalation: not yet ported — Python `crowdsec-cf-sync` continues
- Lua `bans.json` push: not ported — nginx enforcement depends on Python

These are tracked in `docs/archive/TEST_GAP_REPORT.md` and are explicitly out of scope for v1.2 per the sprint spec.

---

## RC Gate

**Repository Gate: GREEN**

All local validation gates pass. All audit findings resolved or accepted. No open critical TODO items. Working tree clean. 109 test packages pass with no data races detected.

---

## Phase 6 — Production Observability

| Component | Status | Notes |
|---|---|---|
| journald integration | ✅ | log/slog JSON format → stdout → journald capture |
| Startup log | ✅ | internal/startuplog writes to /var/log/security-automation/startup.log before first sync |
| logrotate | ✅ | copytruncate strategy; no SIGUSR1 required |
| /healthz | ✅ | Always 200 OK |
| /readyz | ✅ | Returns 200 when daemon ready |
| /statusz | ✅ | Runtime status for operator inspection |
| /metrics | ✅ | Prometheus-compatible endpoint |
| Audit trail | ✅ | All mutation surface events logged to audit sink |
| LogsDirectory= in unit | ✅ | systemd creates /var/log/security-automation before ExecStart |

### Operator Quick-Diagnosis Commands (run on production host)

```bash
# Service health
systemctl is-active cf-sync.service
journalctl -u cf-sync.service -n 50 --no-pager

# Startup log
cat /var/log/security-automation/startup.log

# HTTP endpoints
curl -sf http://127.0.0.1:9090/healthz
curl -sf http://127.0.0.1:9090/readyz
curl -sf http://127.0.0.1:9090/statusz | jq .

# Shadow agreement (if still in shadow phase)
cat /var/lib/cf-sync/shadow/SHADOW_MODE_REPORT.md | \
  grep "7-day agreement\|Status\|in_sync\|consecutive"
```

### Note

Shadow completion threshold (≥99.9% agreement, ≥20 consecutive in-sync cycles) is documented in
`docs/runbooks/CUTOVER_RUNBOOK.md` (Pre-Cutover Checklist, Step 1). The shadow runbook does not
restate this threshold — operators should reference the cutover checklist for the GO criterion.

---

## Phase 7 — Final Cutover Verdict

### Gates Summary

| Gate | Status |
|---|---|
| Repository (all local validation) | ✅ GREEN |
| All v1.2 audit findings resolved | ✅ GREEN |
| TODO.md — no open critical items | ✅ GREEN |
| Runbook service names corrected | ✅ GREEN |
| Shadow gate (production host) | ⏳ PENDING HOST VERIFICATION |

### Shadow Gate (host-required)

Shadow agreement reported at **~99.98%** in the pre-v1.2 sprint. To confirm before cutover:

```bash
cat /var/lib/cf-sync/shadow/SHADOW_MODE_REPORT.md | \
  grep "7-day agreement\|Status\|in_sync\|consecutive"
```

Expected: 7-day agreement ≥ 99.9%, no unresolved drift.

### Verdict

**READY FOR CUTOVER** — pending shadow gate verification on production host.

Once shadow gate is confirmed ≥ 99.9%, follow `docs/runbooks/CUTOVER_RUNBOOK.md` for the
controlled-authority promotion sequence.
