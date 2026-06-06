# Pre-V1.2 Final Hardening Report

**Date:** 2026-06-06
**Branch:** main

---

## Files Modified

| File | Change |
|---|---|
| `internal/config/config.go` | Added `ResolveAdminToken() (string, error)` |
| `cmd/cf-sync/daemon_runtime.go` | Updated `newAuthenticator()` to use `config.ResolveAdminToken()`; gofmt fix |
| `docs/runbooks/FIRST_BOOT.md` | Added `CF_SYNC_API_TOKEN_FILE` to pre-boot env list |
| `docs/security/SECURITY.md` | Added file-backed token to secret handling section |

## Tests Added

| Test | File | Covers |
|---|---|---|
| `TestResolveAdminToken` (5 subtests) | `internal/config/config_test.go` | File wins over env, missing file errors, empty file errors, env fallback, neither set errors |
| `TestNewAuthenticator/with_file_token` | `cmd/cf-sync/daemon_runtime_test.go` | File token accepted, env token rejected |
| `TestNewAuthenticator/file_missing_fails_startup` | `cmd/cf-sync/daemon_runtime_test.go` | Missing file causes startup error |
| `TestFirstBootEndToEnd` | `internal/ui/auth/firstboot_integration_test.go` | bcrypt hash, no plaintext, 0600 perms, idempotency, restart safety |
| `TestConfigPrecedenceLayerOrdering` | `internal/config/config_test.go` | 3-layer override chain (defaults < YAML < env vars) |

## Findings Confirmed

### CSRF already covered (T2)
**Status:** RESOLVED (pre-existing)
`TestMutationSurface_CSRFAndMethodEnforcement` in `internal/ui/mutation_surface_test.go`
covers POST /ui/settings/password/change, /logout, /forensic, /intelligence, and all /admin/providers/* routes. All return 403 without a valid CSRF token. All 10 POST mutation handlers call `s.validCSRF(r)`. The audit finding was resolved prior to this sprint.

## Findings Disproven

None — all flagged items from the pre-sprint audit were either confirmed resolved or confirmed never present.

## Validation Results

| Check | Result |
|---|---|
| `gofmt -l .` | Clean |
| `go vet ./...` | Clean |
| `go build ./...` | Clean |
| `go test ./...` | All PASS |
| `go test -race ./...` | No DATA RACE |

## Known Remaining Issues

- No known production blockers.
- `internal/cloudflare/transport` and `internal/crowdsec/adapter` still have no unit tests (pre-existing, out of scope for this sprint per the spec's "No feature expansion" constraint).

---

## Final Verdict

**READY FOR V1.2**

All pre-v1.2 hardening gaps are closed:
- CF_SYNC_API_TOKEN_FILE implemented with fail-closed semantics (file wins, missing/empty file is a startup error)
- CSRF coverage confirmed on all mutation routes (10 handlers, 4 originally-flagged routes)
- First-boot E2E test proves bcrypt hash, no plaintext, idempotency
- Config precedence documented and tested (3 layers)
- Documentation updated to reflect current behavior
- All tests pass under race detector
