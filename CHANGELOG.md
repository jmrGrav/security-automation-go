# Changelog

All notable changes to this project will be documented in this file.

## [v1.5.4] — 2026-06-10

### Summary

Operational and First-Run UI finalization. Unified management mode introduced. Generic/temporary passwords removed in favor of mandatory wizard-based creation. Default ports standardized (UI: 9091, Metrics: 9092). Debian packaging lifecycle hardened (stop on remove, full cleanup on purge). SQLite concurrency hardened. Dead code from auth migration removed.

### Features

- **Unified Management Mode** — The `-mode ui` flag now acts as a complete management service. On fresh installations, it provides the setup wizard. Once setup is complete, it automatically starts the full security orchestration in the background alongside the Web UI.
- **Mandatory Password Creation** — Removed all generic passwords (`CHANGE_ME_ON_FIRST_BOOT`) and automatically generated setup secrets. Operators must now explicitly create their administrator password during the first-run wizard.
- **Port Standardization** — Default UI port set to `9091` and Metrics/API port to `9092`. Both listen on `127.0.0.1` (localhost only).

### Security / Reliability

- **SQLite PRAGMA ordering** — `PRAGMA busy_timeout=5000` is now set before `PRAGMA journal_mode=WAL` in both `New()` and `Reopen()`. This ensures the retry timeout is active during WAL mode negotiation, preventing `SQLITE_BUSY` errors on concurrent first-open in UI mode (`internal/storage/sqlite/db.go`).
- **Migration TOCTOU** — Each schema migration now runs inside a `BEGIN IMMEDIATE` transaction with an in-transaction `EXISTS` check before applying. Prevents duplicate-migration errors when two goroutines open the same database simultaneously on fresh install (`internal/storage/manager/migrator.go`).
- **Smoke test correctness** — Fixed two bugs in `smoke_test.go` (build tag `smoke`): `TestSmoke_SetupWizardAccessible` now uses an incomplete-setup server; `TestSmoke_WrongPasswordRejected` uses the correct `password=` form field and asserts 401.

### Packaging

- **Lifecycle Hardening** — Added `prerm` script to ensure the `cf-sync` service is stopped before package removal.
- **Improved Purge** — `apt purge` now cleans up all canonical directories (`/etc`, `/var/lib`, `/var/log` for `security-automation-go`) and safely removes empty legacy paths used during migration.
- **Path Normalization** — All internal paths and defaults updated to the canonical `/var/log/security-automation-go` directory.
- **Version injection** — `make package` now injects `$(VERSION)` into `DEBIAN/control` via `sed` before `dpkg-deb --build`, ensuring `dpkg --info` reports the correct version.
- **Legacy service cleanup** — `postinst` removes any `/etc/systemd/system/cf-sync.service` left over from pre-package installs so the package-owned unit in `/lib/systemd/system/` takes precedence.

### Cleanup

- Removed `GenerateInitialPassword`, `VerifyInitialPassword`, and `InvalidateInitialPassword` (dead code — no production callers after auth migration).
- Removed `InitialPasswordFile` config field (set but never read in production).
- Removed `func runDaemon` wrapper (replaced by `runDaemonWithLocker` which is called directly).
- Removed dead `"UI_SECRET"` env map entries from test helpers (env var not read by config).
- Corrected `.env.example` paths to canonical `/var/lib/security-automation-go`.

### Documentation

- Updated `README.md`, `FIRST_BOOT.md`, and `PACKAGING.md` with new ports and setup procedures.

---

## [v1.5.3] — 2026-06-08

### Summary

Hardening sprint. Brooks Phase 2 review findings addressed. VACUUM INTO SQL construction hardened (parameterized query), API/auth boundary test coverage added, smoke test suite introduced. No API or behavioral changes.

### Security

- **VACUUM INTO hardened** — `ExportHotSnapshot` now uses a parameterized query (`VACUUM INTO ?`) instead of string concatenation. Path validation extended to reject semicolons, null bytes, and newlines in addition to the existing absolute-path, traversal, and quote checks. Fix: `internal/storage/sqlite/db.go`.

### Testing

- **API/auth boundary coverage** — Added targeted tests for `internal/api/auth`, `internal/api/middleware`, `internal/api/handlers`, and `internal/api/handlers/v2`. Coverage: auth=100%, handlers=90.5%, v2=92.6%, middleware=84.4%. Tests verify: auth required, unauthorized rejected, scope enforcement, malformed JSON → 400, state machine transitions via API.
- **Smoke test suite** — Added `internal/ui/smoke_test.go` (`//go:build smoke`). Scenarios: server boots, anonymous access rejected, wizard accessible before setup, login succeeds, wrong password rejected, authenticated dashboard/health reachable, mutation endpoint requires CSRF. Run with `go test -tags=smoke ./internal/ui/...`.

### Documentation

- `docs/issues/SECURITY_BACKLOG.md`: updated with hardening sprint entries.
- `docs/COVERAGE_POLICY.md`: added coverage targets and guidance.

---

## [v1.5.2] — 2026-06-08

### Summary

Resilience patch release. Two findings from the June 2026 Gemini adversarial chaos audit fixed (C1, C5). Three remaining findings closed with technical justification. No API or behavioral changes.

### Security / Reliability

- **C1 fixed** — Daemon liveness: `Scheduler.Start()` now calls `recoverStaleState()` on startup. If the state file shows a non-terminal status (Discovering, Planning, AwaitingApproval, Executing, Validating, RollbackRequired, RollingBack) — left by a previous crash between `store.Save()` and `PublishEvent()` — it is immediately reset to `StatusFailed` via the state machine. The scheduler can then retry on the next tick via `StatusFailed → StatusDiscovering`. Intentional operator states (Paused, Quarantined) are preserved (`internal/runtime/scheduler/stateful/scheduler.go`).
- **C5 fixed** — Pagination partial delivery: `TraverseAll()` now compares total items collected against `ResultInfo.TotalCount` after all pages are fetched. If fewer items were received than the API reported, the function fails closed with an error rather than returning a partial snapshot. Note: does not detect zeroed-metadata false-empty responses (TotalCount=0 on a non-empty resource) — documented limitation (`internal/cloudflare/pagination/pagination.go`).

### Closed (no action)

| ID | Finding | Rationale |
|----|---------|-----------|
| C2 | Non-deterministic OperationID | Duplicate of SEC-012 — intentional per-attempt uniqueness |
| C3 | Cloudflare POST idempotency | Snapshot diffing (StableIdentityKey) already prevents duplicates; confirmed via reconciliation planner code path |
| C4 | Recorder unbounded RAM growth | `AuthorizeFederated` has no production callers; recorder never accumulates entries during normal daemon operation |

---

## [v1.5.1] — 2026-06-08

### Summary

Security patch release. Two low-severity UI findings fixed following the June 2026 Gemini red-team audit. All remaining audit findings closed with technical justification. No API or behavioral changes.

### Security

- **SEC-005 fixed** — `handleSetupStep1` now redirects to `/login` when setup is complete, preventing the `SecretFile` path from being revealed to unauthenticated visitors post-setup (`internal/ui/setup_wizard.go`).
- **SEC-007 fixed** — `handleChangePassword` now invalidates all active sessions immediately after a successful password update. Users must re-authenticate; the response redirects to `/login` (`internal/ui/settings.go`).

### Closed (no action)

Following independent code revalidation, the remaining 8 open audit findings are closed:

| ID | Finding | Rationale |
|----|---------|-----------|
| SEC-004 | Rate limiter O(n) | Local UI; ≤5 clients in practice; sub-µs scan |
| SEC-006 | crypto/rand panic | Never fails on Linux 3.17+; net/http recovers panics |
| SEC-008 | OpenResty/Lua review | No actionable finding; process recommendation only |
| SEC-009 | SQLite recovery review | No actionable finding; process recommendation only |
| SEC-010 | Evidence recorder volatile | Diagnostic only; enforcement unaffected; V3 SQLite path is the system of record |
| SEC-011 | Drift memory volatile | Analytics only; enforcement unaffected |
| SEC-012 | Non-deterministic OperationID | Intentional — per-attempt uniqueness; `IdempotencyKey` handles correlation |
| SEC-013 | decisions.log O(n) scan | Bounded at ~10k lines/day with standard logrotate; sub-ms |

---

## [v1.5.0] — 2026-06-08

### Summary

First release with a validated first-run wizard, encrypted credential store, and complete CrowdSec Go integration. The historical Python runtime is retired from the critical path; remaining Python scripts are kept only for rollback/archival reference.

### Added

- **First-run setup wizard** — 10-step guided install: password, admin setup, Cloudflare token, optional enrichment keys (AbuseIPDB, BetterStack, AI providers), CrowdSec LAPI key, runtime summary, production enable. Tested end-to-end via `TestUIFreshInstallWizardAndConservativeRestart`.
- **Encrypted CredentialStore** — AES-GCM per-secret SQLite store (`internal/storage/sqlite/credential_store.go`). All operator secrets (Cloudflare, AbuseIPDB, BetterStack, AI keys, CrowdSec LAPI) flow exclusively through this store at runtime. No plaintext secrets in env files after first boot.
- **CrowdSec poller — Go replacement** (`internal/crowdsec/poller/`) — complete port of `crowdsec-poller.py`. Reads LAPI key from encrypted CredentialStore; fail-closed (returns error) if key absent.
- **CrowdSec UI/UX sprint**:
  - Auto-discovery: HTTP probe (8080/8088), AppSec port 7422, `cscli` binary — `internal/detect/detectors.go`
  - Health center: three new checks — `crowdsec`, `crowdsec-poller`, `crowdsec-appsec` with GREEN/YELLOW/RED states
  - Admin panel: set/replace/delete/test LAPI key via encrypted CredentialStore — `internal/ui/crowdsec_admin.go`
  - Wizard step 8: CrowdSec LAPI key (optional, skippable, stored in CredentialStore)
- **`docs/AI_HANDOFF.md`** — rapid context document for AI assistants and future contributors.
- **Secret path canonicalization** — legacy layout detector; secret loading refuses to silently fallback once canonical directory exists.
- **First-boot URL log** — prints the UI URL to stdout/journal on first start; gated behind production enable flag.

### Changed

- Wizard stepped from 9 to 10 steps (CrowdSec step 8 inserted; runtime summary → step 9; production enable → step 10).
- `internal/config/config.go`: `PollerLAPIKey` is runtime-only; `CS_POLLER_LAPI_KEY` env loading removed.
- `cmd/crowdsec-sync/main.go`: opens SQLite CredentialStore at startup to inject LAPI key; no env/YAML fallback.
- Health page no longer exposes `state.db` path in environment detection panel.
- SQLite `db_path` detail removed from `DetectSQLite` output (internal path not surfaced to UI).

### Retired / removed

- **ModSecurity** — retired, replaced by CrowdSec AppSec. Stubs return `ErrNotImplemented`.
- `CS_POLLER_LAPI_KEY` env variable — never set; key comes from CredentialStore only.
- `internal/ui/ai_key_contract_test.go` — superseded by `provider_boundary_test.go`.

### Security

- Confirmed: no real LAPI keys or API tokens in git history or working tree.
- `crowdsec.lapi_key` redacted automatically by `isSensitiveAuditKey` (substring `"api_key"`).
- CSRF protection on all admin routes.
- Key never displayed in UI response, log, or audit trail after initial set.

### Known limitations

- `internal/cloudflare/transport` (Cloudflare mutations) and `internal/crowdsec/adapter` (cscli bans): no unit tests yet — these boundaries are integration-tested via the running daemon.
- Recidivist escalation, `/24` auto-ban, and allowlist-sync flows remain in Python stubs (v1.5.1 backlog).
- RPM package skipped — `rpmbuild` not available in CI; `.deb` only.

---

## [v1.1.1] and earlier

Pre-release development. Python remains the source of truth for all prior versions.

[v1.5.0]: https://github.com/jmrGrav/security-automation-go/releases/tag/v1.5.0
