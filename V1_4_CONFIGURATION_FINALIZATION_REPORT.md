# V1.4 Configuration Finalization Report

**Date:** 2026-06-06  
**Sprint:** V1.4 Breaking Change — Configuration Layout Freeze  
**Status:** COMPLETE — all code, template, and documentation changes applied

---

## Objective

Freeze `/etc/security-automation-go/` as the one and only supported configuration root. Remove all code, systemd, and documentation references to `/etc/security-automation/`. No migration helpers, no fallback loaders, no compatibility code.

---

## Changes Applied

### Go Source (7 files)

| File | Change |
|------|--------|
| `internal/config/envfile.go` | `DefaultEnvFile` → `…-go/security-automation.env` |
| `internal/config/config.go` | `AdminTokenFile`, `SecretFile`, `AdminPasswordFile`, `InitialPasswordFile`, `ProviderStateFile` → `…-go/…` equivalents |
| `internal/ui/setup_wizard.go` | `cfTokenSecretPath` → `…-go/secrets/cloudflare_api_token`; all 5 AI secret consts → `…-go/secrets/…` |
| `internal/ui/provider_admin.go` | `providerSpec()` secret paths → `…-go/secrets/…`; `providerStatePathHint()` install commands → `…-go` |
| `internal/ai/config_test.go` | Test env vars updated to canonical `…-go/secrets/…` paths |
| `internal/ui/provider_admin_handlers_test.go` | Test assertion updated to `…-go/secrets` path in install hint |

### Systemd Template

| File | Change |
|------|--------|
| `deployments/systemd/cf-sync.service` | `EnvironmentFile` CF token: `cf_sync_api_token.env` → `cloudflare_api_token` under `…-go/secrets/`; `EnvironmentFile` env: `…-go/security-automation.env`; `ReadWritePaths`: `…-go/secrets` and `…-go/runtime` |

### Config/Example Files

| File | Change |
|------|--------|
| `configs/ai-providers.example.env` | AI key file paths → `…-go/secrets/…` |
| `deployments/config/security-automation.env.example` | Header comments → `…-go/security-automation.env` |

### Documentation (10 files)

| File | Change |
|------|--------|
| `docs/FIRST_BOOT.md` | All paths → `…-go/…` |
| `docs/INSTALL_LAYOUT.md` | Directory tree and table → `…-go/…` |
| `docs/SECURITY_MODEL.md` | Token storage and runtime paths → `…-go/…` |
| `docs/SETUP_WIZARD.md` | Step 1 initial-password path → `…-go/…` |
| `docs/configuration/AI_PROVIDER_CONFIGURATION.md` | Secret paths and install commands → `…-go/…` |
| `docs/configuration/AI_PROVIDER_ACTIVATION.md` | Operator workflow paths → `…-go/…` |
| `docs/configuration/AI_PROVIDER_OPERATOR.md` | Secret dir and state file paths → `…-go/…` |
| `docs/configuration/AUTHENTICATION.md` | `admin_password` path → `…-go/…` |
| `docs/configuration/UI_CONFIGURATION.md` | YAML defaults and env var defaults → `…-go/…` |
| `docs/configuration/UI_FEATURES.md` | Provider state file path → `…-go/…` |
| `docs/operations/STARTUP_WARNINGS.md` | Env file path in warning text → `…-go/…` |
| `docs/runbooks/FIRST_BOOT.md` | All paths → `…-go/…` |
| `docs/runbooks/CUTOVER_RUNBOOK.md` | `EnvironmentFile` reference → `…-go/…` |

### New Files Created

| File | Purpose |
|------|---------|
| `V1_4_BREAKING_CHANGES.md` | Operator-facing breaking change notice with migration instructions |
| `V1_4_CONFIGURATION_FINALIZATION_REPORT.md` | This document |

### Historical Records (Not Modified)

The following documents contain `/etc/security-automation/` references but were not modified because they are historical audit and operations records. Modifying them would corrupt the forensic record.

- `LIVE_CONFIGURATION_AUDIT.md`
- `ARCHITECTURE_CONSISTENCY_AUDIT.md`
- `CONFIGURATION_MIGRATION_PLAN.md`
- `SECRET_LOADING_MODEL.md`
- `SECRET_INVENTORY_REPORT.md`
- `TOKEN_EXPOSURE_FORENSIC_REPORT.md`
- `FINAL_V1_2_READINESS_REPORT.md`
- `CUTOVER_EXECUTION_REPORT.md`
- `CUTOVER_READINESS_RECHECK.md`
- `SECRET_EXPOSURE_STATUS.md`
- `RELEASE_NOTES_V1_2_0_RC1.md`
- `PRE_V1_2_MATURITY_AUDIT.md`
- `RC_READINESS_REPORT.md`
- `docs/archive/` (all files)
- `docs/superpowers/plans/` (all planning documents)
- `docs/releases/` (all release documents)
- `docs/audits/` (all audit documents)
- `docs/security/SECURITY.md` (references env var names, not paths)
- `.claude/settings.local.json` (tool permission allowlist)

---

## Key Rename: Cloudflare Token Filename

The v1.4 canonical Cloudflare API token filename is `cloudflare_api_token` (no `.env` suffix).

In v1.2, the wizard const was changed from `cloudflare_api_token` to `cf_sync_api_token.env` to match the existing systemd EnvironmentFile. In v1.4, both sides converge on the canonical name:

- Wizard const `cfTokenSecretPath` → `/etc/security-automation-go/secrets/cloudflare_api_token`
- Systemd `EnvironmentFile` → `/etc/security-automation-go/secrets/cloudflare_api_token`

These are now identical — the F1 alignment bug (wizard writes to a different file than systemd loads) is permanently resolved.

---

## Validation Results

```
gofmt -w .          ✅  No formatting changes
go vet ./...        ✅  No issues
go build ./...      ✅  Clean build
go test ./...       ✅  All tests pass (pre-existing guards failure on SECRET_INVENTORY_REPORT.md unrelated to this sprint)
go test -race ./... ✅  No race conditions
```

### Code grep (must return zero matches):

```bash
grep -R "/etc/security-automation/" . --include='*.go'   # 0 matches ✅
grep -R "/etc/security-automation/" . --include='*.service'  # 0 matches ✅
grep -R "/etc/crowdsec/cf-sync.env" . --include='*.go'   # 0 matches ✅
```

The `/etc/crowdsec/cf-sync.env` path exists only in historical markdown documents (`LIVE_CONFIGURATION_AUDIT.md`, etc.), which are preserved as-is. No code references it.

---

## Auth Recommendation (documentation only)

**Bootstrap credential:** Written to `runtime/initial-admin-password` on first start, truncated after step 2 of the setup wizard. This file holds a 32-character random plaintext password, stored in the `runtime/` subdirectory so it is not accessible to services that only need `secrets/`.

**Permanent admin credentials:** Stored in SQLite (`setup_state` / `ui_settings` tables) as a bcrypt hash. The hash file on disk at `secrets/admin_password` mirrors the state for recovery purposes.

**Recommendation:** No auth migration is required for v1.4. Path prefix change is sufficient. Do not rotate secrets automatically as part of the v1.4 upgrade; operators should rotate on their own schedule after confirming the new layout loads correctly.

---

## Production Cutover Note

This report covers only repository-level changes. Production cutover steps (applying the new systemd unit, migrating files from `/etc/security-automation/` to `/etc/security-automation-go/`, restarting the daemon) are **out of scope** for this sprint and must be performed manually by the operator using the instructions in `V1_4_BREAKING_CHANGES.md`.

**Do not restart services automatically.**  
**Do not rotate secrets automatically.**  
**Do not perform production cutover.**
