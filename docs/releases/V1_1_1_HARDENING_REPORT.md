# v1.1.1 Hardening Report

**Date:** 2026-06-05  
**Branch:** main  
**Base commit:** 51a56e7  
**Hardening commits:** d2b256e → d7cf7de (13 commits)

---

## 1. Findings Remediated

All audit findings from the Gemini + Brooks read-only maturity audit (2026-06-03) are closed.

| ID | Severity | Finding | Status |
|---|---|---|---|
| H-1 | High | Missing CSRF on `POST /ui/settings/password/change` | ✅ Fixed |
| Phase 4 | High | Hardcoded `"admin-token"` + all-interface bind in cf-sync API server | ✅ Fixed |
| M-1 | Medium | SQLite pragma string concatenation (WALCheckpoint, ExportHotSnapshot, requireColumn) | ✅ Fixed |
| M-2 | Medium | `AllowlistEntry.Comment` unvalidated before passing to cscli exec | ✅ Fixed |
| M-3 | Medium | Missing CSRF on POST /logout, POST /forensic, POST /intelligence | ✅ Fixed |
| L-1 | Low | Session cookies using SameSite=Lax instead of Strict | ✅ Fixed |
| L-2 | Low | Rollback planner OpUpdate silently re-applies wrong payload | ✅ Fixed |
| L-3 | Low | 12 runtime packages with no tests (ha, governor, invariants, health prioritised) | ✅ Fixed |
| L-4 | Low | `isSensitiveAuditKey` missing "bearer" key name | ✅ Fixed |
| L-5 | Low | `RotateBackups` silently discards `os.Remove` errors | ✅ Fixed |

---

## 2. Tests Added

| Finding | New Tests | File |
|---|---|---|
| H-1 | `TestChangePassword_MissingCSRF`, `TestChangePassword_InvalidCSRF`, `TestChangePassword_ValidCSRF` | `internal/ui/settings_test.go` |
| M-3 | `TestLogout_RequiresCSRF`, `TestLogout_ValidCSRF`, `TestForensicLookup_RequiresCSRF`, `TestIntelligenceLookup_RequiresCSRF` | `internal/ui/server_test.go` |
| M-1 | `TestWALCheckpoint_RejectsUnknownMode`, `TestWALCheckpoint_AcceptsValidModes`, `TestExportHotSnapshot_RejectsInvalidPaths` | `internal/storage/sqlite/db_test.go` |
| L-5 | `TestRotateBackups_ReturnsErrorOnReadOnly` | `internal/storage/sqlite/db_test.go` |
| M-2 | `TestValidateComment` (10 cases) | `internal/crowdsec/client_validation_test.go` |
| L-4 | `TestIsSensitiveAuditKey_Bearer` (6 cases) | `internal/ui/audit_redaction_test.go` |
| L-3 | 23 tests across 5 packages: ha, ha/backends/file, governor, invariants, health | 5 new `*_test.go` files |
| L-2 | `TestGenerateRollbackBatch_OpUpdateReturnsError`, `TestGenerateRollbackBatch_OpDeleteGeneratesCreate` | `internal/rollback/planner/planner_test.go` |
| Phase 4 | `TestNewAuthenticator` updated (with_token, empty_token) | `cmd/cf-sync/daemon_runtime_test.go` |

**Total new/updated tests:** ~50 test cases across 10 packages.

---

## 3. Coverage Changes

New packages now covered (previously zero tests):

| Package | Tests Added |
|---|---|
| `internal/runtime/ha` | 3 |
| `internal/runtime/ha/backends/file` | 4 |
| `internal/runtime/governor` | 6 |
| `internal/runtime/invariants` | 5 |
| `internal/runtime/health` | 5 |
| `internal/rollback/planner` | 2 |
| `internal/crowdsec` (validation) | 10 |

---

## 4. Admin Token Verdict

**CONFIRMED VULNERABILITY — FIXED**

See `docs/audits/ADMIN_TOKEN_FINAL_VERDICT.md` for full details.

**Summary:**
- `cmd/cf-sync/daemon_runtime.go` hardcoded `"admin-token"` as the API auth token
- Server defaulted to `:9090` (all network interfaces)
- Any host reaching port 9090 could authenticate with `Authorization: Bearer admin-token`

**Fix applied:**
1. Token loaded from `CF_SYNC_API_TOKEN` env var — daemon fails startup if unset
2. Default bind changed from `:9090` to `127.0.0.1:9090`

**Other TODOs reviewed:** All classified as FUTURE WORK except the rollback planner OpUpdate bug (fixed as L-2).

---

## 5. Security Improvements

| Change | Impact |
|---|---|
| CSRF on password change | Prevents CSRF credential rotation even if attacker knows current password |
| CSRF on logout/forensic/intelligence | Eliminates CSRF logout and unintended external lookup triggers |
| CSRF audit records on rejection | All CSRF rejections now appear in the audit trail |
| SameSite=Strict on session cookie | Stronger CSRF defence — cookies not sent on any cross-site navigation |
| Admin token from env | Hardcoded credential eliminated; token never appears in source |
| Loopback-only API bind | cf-sync runtime API no longer reachable from network without explicit configuration |
| SQLite input validation | WALCheckpoint, ExportHotSnapshot, requireColumn reject malformed inputs |
| Comment validation in cscli | Null bytes, control chars, invalid UTF-8 rejected before reaching subprocess |
| `"bearer"` redacted in audit | Bearer tokens in audit key names are now suppressed |
| RotateBackups error visibility | Disk-full backup deletion failures are no longer silently swallowed |
| Rollback OpUpdate explicit error | Silent wrong-state compensation replaced with an actionable error |

---

## 6. Regression Results

All commands run on final commit `d7cf7de`:

```
gofmt -l ./...          → no output (clean)
go vet ./...            → no output (clean)
go build ./...          → no output (clean)
go test ./...           → all ok, 0 FAIL  (549 Go files)
go test -race ./...     → all ok, 0 DATA RACE
go test -tags=soak ./internal/testing/... → ok
```

Full test suite: 100% pass. Race detector: clean.

---

## 7. Remaining Technical Debt

None of the items below are blockers for v1.1.1.

| Item | Classification | Notes |
|---|---|---|
| 66 packages with no tests | Accepted debt | Many are thin wrappers or scaffolding. L-3 addressed the 5 highest-risk ones. |
| `rollback/validator/validator.go:43` TODO | FUTURE WORK | Registry integration not yet planned |
| `runtime/invariants/engine.go:71` TODO | FUTURE WORK | Graph package integration not yet scoped |
| `policy/bundles/activation/manager.go` TODOs | FUTURE WORK | Bundle signing, compat checks are future |
| `cloudflare/models.go` TODOs | FUTURE WORK | GraphQL/pagination stubs for future discovery |
| `MutationOperation.PreviousPayload` missing | FUTURE WORK | Required before rollback OpUpdate can be implemented |
| SameSite=Strict logout form uses JS fetch | Minor | Implemented via fetch + csrf-token meta tag; works correctly |
| `validCSRF` reads form body (implicit ParseForm) | Low | Idempotent in Go; no bug. Document for future readers. |

---

## 8. Release Recommendation

**GO**

All audit findings are remediated. No regressions. Race detector clean. Soak tests pass. Shadow guarantees, replay guarantees, recovery guarantees, and SQLite durability guarantees are preserved. The admin token vulnerability (the highest-risk finding) is fully closed.

**Pre-push checklist:**
- [ ] Set `CF_SYNC_API_TOKEN` in production systemd unit before deploying cf-sync daemon
- [ ] Existing `--metrics-addr` overrides that use `:9090` will continue to work (flag still accepts any address)
- [ ] UI sessions will be re-established after deploy (SameSite=Strict is a cookie attribute change)
