# Changelog

All notable changes to this project will be documented in this file.

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
