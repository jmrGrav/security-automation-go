# V1.4 Final Hardening Report

**Date:** 2026-06-07  
**Branch:** main  
**Head commit:** 1fba861  
**Sprint:** Architecture Hardening Only — Feature development frozen

---

## Verdict

**READY FOR PRODUCTION CUTOVER**

All 12 hardening phases completed. Full test suite passes under the race detector. No blockers. No open findings.

---

## Phase Summary

| Phase | Title | Status | Commit |
|-------|-------|--------|--------|
| 1 | Storage path finalization | DONE | 3676d62 |
| 2 | SQLite auth finalization | DONE | 3a75101 |
| 3 | Systemd consolidation audit | DONE | 7d6c4d8 |
| 4 | gitleaks/trufflehog CI | DONE | 52d0520 |
| 5 | Secret exposure review | DONE | c2ccb8e |
| 6 | Production safety gates | DONE | eddc179 |
| 7 | Recovery model | DONE | 1ccabe4 |
| 8 | Installer readiness | DONE | 5ec47c0 |
| 9 | Upgrade safety | DONE | c557f5a |
| 10 | Packaging gap analysis | DONE | 5d146c3 |
| 11 | Full validation (race) | DONE | 1fba861 |
| 12 | This report | DONE | — |

---

## Phase Detail

### Phase 1 — Storage Path Finalization (3676d62, 2d904c8)

Canonical paths locked in:

| Resource | V1.1 path | V1.4 canonical |
|----------|-----------|----------------|
| Runtime data | `/var/lib/cf-sync/` | `/var/lib/security-automation-go/` |
| Config root | `/etc/cf-sync/` | `/etc/security-automation-go/` |
| Binaries | `/usr/local/bin/cf-sync` etc. | `/usr/local/bin/cf-sync`, `/usr/local/bin/cf-shadow`, etc. |
| SQLite DB | `/var/lib/cf-sync/state.db` | `/var/lib/security-automation-go/state.db` |

All config references, systemd units, install scripts, and documentation updated to canonical paths. No `cf-sync` path remnants in active configuration.

### Phase 2 — SQLite Auth Finalization (3a75101)

- Admin password hash stored exclusively in `ui_settings["admin_password_hash"]` (SQLite, migration 15)
- No password files on disk after first login
- `bcrypt` cost 12 for production hashes
- `auth.HashPassword` / `auth.VerifyPassword` are the only call sites
- File-based bootstrap code (`InitializeBootstrapPassword`, `BootstrapState`, `ClearBootstrapState`) fully removed from production and test code
- All 6 UI test files rewritten to use in-memory `testAdminStore` — no filesystem bootstrap required

### Phase 3 — Systemd Consolidation Audit (7d6c4d8)

Secondary units aligned to v1.4 canonical paths:
- `cf-cleanup.service` — ExecStart, WorkingDirectory, EnvironmentFile updated; hardening directives added
- `crowdsec-sync.service` — same
- `cf-allowlist-sync.service` — same
- `cf-shadow.service` — same; EnvironmentFile split into base + shadow-specific env

All units now share a consistent security posture: `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `ProtectKernelTunables=yes`, `ProtectControlGroups=yes`, `NoNewPrivileges=yes`, `ReadWritePaths` scoped to `/var/lib/security-automation-go` and `/etc/security-automation-go/secrets`.

### Phase 4 — gitleaks/trufflehog CI (52d0520)

- `.github/workflows/ci.yml` — added `secret-scan` job (gitleaks) and `trufflehog` job
- `.gitleaks.toml` — allowlists for test fixtures and documentation examples
- `scripts/install-hooks.sh` — installs gitleaks pre-commit hook locally
- CI blocks merge on any detected secret

### Phase 5 — Secret Exposure Review (c2ccb8e)

All secret surface reviewed:
- Cloudflare tokens: only written to SQLite `ui_settings` and `secrets/` directory; never logged
- Admin password hash: only in SQLite; never returned to API or logged
- Initial password: logged as file path only, never as value — enforced by code review and test `TestNoSecretLeakage`
- API tokens in UI: masked on display after save
- No tokens in environment variables at runtime (EnvironmentFile loads secrets; env vars not inherited by child processes)

### Phase 6 — Production Safety Gates (eddc179)

- `forcePasswordChangeMiddleware` — redirects to `/ui/password/change` on every request when no password hash exists in SQLite
- `isBootstrapActive` — returns true when store has no `admin_password_hash`
- Test coverage: 5 tests covering redirect, passthrough, password-change path exclusion, nil-store edge case, and 3 `isBootstrapActive` sub-cases

### Phase 7 — Recovery Model (1ccabe4)

`RECOVERY_MODEL.md` documents operator recovery paths for:
- Admin password forgotten
- SQLite database corrupted or missing
- UI secret rotation
- DynamicUser UID drift (state.db ownership)
- Lockout during wizard (incomplete setup)
- SSH-only access recovery

All recovery paths are runbook-ready: exact commands, no external dependencies.

### Phase 8 — Installer Readiness (5ec47c0)

`docs/INSTALL_LAYOUT.md` updated to v1.4 layout:
- Secrets directory contents: `admin_token`, `ui_secret`, `cf-shadow.env` (not `admin_password`)
- Runtime directory: `/var/lib/security-automation-go/` (not `/etc/`)
- Shadow installer binary path fixed to `/usr/local/bin/cf-shadow`
- SQLite auth model explained; no mention of bootstrap password file

### Phase 9 — Upgrade Safety (c557f5a)

`UPGRADE_COMPATIBILITY_REPORT.md` documents:
- V1.1 → V1.4 migration: symlink strategy for backward-compatible path transitions
- SQLite migration 15 is additive; no existing tables touched
- Systemd unit upgrade: `systemctl daemon-reload && systemctl restart` sequence
- Rollback path: keep v1.1 binary, revert symlinks, no data loss

### Phase 10 — Packaging Gap Analysis (5d146c3)

`PACKAGING_GAP_ANALYSIS.md` documents gaps for .deb/.rpm/tar.gz packaging:
- No `postinst` script for first-run DB init and service enable
- No `postrm` for cleanup of `/var/lib/security-automation-go`
- No package-level `%config(noreplace)` for env files
- Tar.gz: no install.sh provided; manual steps documented

Gaps are known and documented. None block the v1.4 cutover (packaging is a post-v1.4 deliverable).

### Phase 11 — Full Validation (1fba861)

**Build:** `go build ./...` — clean  
**Vet:** `go vet ./...` — clean  
**Format:** `gofmt -l internal/` — no unformatted files  
**Tests (no race):** `go test -timeout 120s ./...` — all pass  
**Tests (race):** `go test -race -timeout 300s ./...` — all pass

Race detector fix: `bcryptCost` changed from `const` to `var` in `auth/password.go`. `auth.OverrideBcryptCost(bcrypt.MinCost)` called from `TestMain` in `internal/ui/testmain_test.go`. Production binaries always hash at cost 12.

---

## Security Invariants Confirmed

| Invariant | Verified by |
|-----------|-------------|
| Admin password hash never logged | `TestNoSecretLeakage` |
| Password change requires valid session | `TestPasswordChangeRequiresValidSession` |
| No session → login required | `TestLoginHandler_ValidCredentials`, `TestLoginHandler_NoHashInStore` |
| CSRF enforced on all state-mutating endpoints | `TestChangePassword_MissingCSRF`, `TestChangePassword_InvalidCSRF` |
| Bootstrap gate redirects until password set | `TestForcePasswordChangeMiddleware_RedirectsWhenNoHash` |
| No plaintext password in any store | `TestFullAuthenticationFlow` |
| Old password rejected after change | `TestFullAuthenticationFlow` |
| bcrypt cost 12 in production | `auth/password.go:var bcryptCost = 12` |
| Secret scan in CI | `.github/workflows/ci.yml` |

---

## Known Non-Blockers

- **Packaging:** .deb/.rpm packaging gaps documented in `PACKAGING_GAP_ANALYSIS.md`. Post-v1.4 work.
- **`DynamicUser=yes` UID drift:** Recovery documented in `RECOVERY_MODEL.md`. Mitigation: use `StateDirectory=` instead of manual `chown` in install scripts.
- **`internal/ui/auth` race test time:** 31s under race detector (bcrypt cost 12, no override in auth package's own TestMain). Acceptable — auth tests are not the hot path.

---

## Commits in This Sprint (newest first)

```
1fba861 fix(test): use bcrypt.MinCost in UI tests to avoid race detector timeout
5d146c3 docs(packaging): add .deb/.rpm/tar.gz gap analysis (Phase 10)
c557f5a docs(ops): add v1.1→v1.4 upgrade compatibility report (Phase 9)
5ec47c0 docs(install): update layout docs and fix shadow installer paths (Phase 8)
1ccabe4 docs(ops): add recovery model for all lockout scenarios (Phase 7)
eddc179 test(ui): add production safety gate tests for forcePasswordChangeMiddleware
c2ccb8e docs(security): add secret exposure status report (Phase 5)
52d0520 feat(ci): add gitleaks and trufflehog secret scanning to CI
7d6c4d8 fix(systemd): align secondary unit files to v1.4 canonical paths
3a75101 feat(auth): replace file-based admin password with SQLite-only storage
3676d62 feat(config)!: v1.4 — replace /var/lib/cf-sync with /var/lib/security-automation-go
2d904c8 feat(config)!: v1.4 — freeze /etc/security-automation-go/ as sole config root
```

---

## Cutover Checklist (Operator)

The following remain as **manual operator steps** per standing constraints (no automatic restarts, no automatic secret rotation):

- [ ] `systemctl daemon-reload`
- [ ] `systemctl restart cf-sync`
- [ ] Verify `/ui/dashboard` loads and prompts password change if first boot
- [ ] Set admin password via UI
- [ ] Confirm service is healthy: `systemctl status cf-sync`
- [ ] Confirm SQLite has password hash: `sqlite3 /var/lib/security-automation-go/state.db "SELECT value FROM ui_settings WHERE key='admin_password_hash'"`

Do not push to production until the checklist above is complete.
