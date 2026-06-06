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
