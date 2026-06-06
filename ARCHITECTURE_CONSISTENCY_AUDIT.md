# Architecture Consistency Audit

**Date:** 2026-06-06
**Sprint:** V1.2 Configuration Consolidation
**Auditor:** Automated architecture review (findings pre-researched)

---

## Executive Summary

The cf-sync daemon has two critical path mismatches that together mean the setup wizard is effectively a no-op: the wizard writes the Cloudflare API token to a filename the systemd unit never loads, and every other setting the wizard writes to SQLite is never read back by the runtime. In addition, the deployed systemd unit has diverged entirely from the canonical repo template, and a legacy parallel config hierarchy is still active on disk — creating two competing configuration sources with no reconciliation.

---

## Findings Summary

| Severity | ID | Finding | Status |
|----------|----|---------|--------|
| CRITICAL | F1 | CF token filename mismatch: wizard writes wrong filename | OPEN |
| CRITICAL | F2 | Wizard settings are write-only: SQLite values never applied at runtime | OPEN |
| HIGH     | F3 | Deployed systemd unit diverged from repo template | OPEN |
| HIGH     | F4 | Legacy config hierarchy still active on disk | OPEN |
| HIGH     | F5 | No systemd unit for UI mode; FIRST_BOOT.md is incorrect | OPEN |
| MEDIUM   | F7 | `ReadWritePaths` missing secrets and runtime directories | OPEN |
| LOW      | F6 | `StartLimitIntervalSec` in wrong systemd section | OPEN |
| OK       | F8 | DefaultEnvFile path is correct | VERIFIED |
| OK       | F9 | Compiled config defaults are correct | VERIFIED |
| OK       | F10 | AI provider secrets written and loaded correctly | VERIFIED |

---

## Finding Detail

### F1: CF Token Filename Mismatch

**Severity:** CRITICAL
**Location:**
- Wizard const: `internal/ui/setup_wizard.go` — `cfTokenSecretPath = "/etc/security-automation/secrets/cloudflare_api_token"`
- Systemd EnvironmentFile: `/etc/systemd/system/cf-sync.service`, line 13 — `EnvironmentFile=/etc/security-automation/secrets/cf_sync_api_token.env`

**Observed:**
The setup wizard (step 4) writes the Cloudflare API token to:
```
/etc/security-automation/secrets/cloudflare_api_token
```
Format: `CF_API_TOKEN=<value>` (env-file format, via `WriteSecretFile`)

The live systemd unit loads its EnvironmentFile from:
```
/etc/security-automation/secrets/cf_sync_api_token.env
```

These are two different filenames. Neither is a symlink to the other.

**Expected:**
Both names must match. `docs/SECURITY_MODEL.md` states the canonical path as `cloudflare_api_token`. The systemd unit must reference the same filename.

**Impact:**
After completing the wizard's step 4, the daemon NEVER loads the token the wizard stored. Every subsequent CF sync attempt fails with an authentication error. The wizard's validation step confirms the token is valid, but the daemon runs without it. This is a silent total failure of the primary sync function.

**Fix:** Phase 1 — Update the EnvironmentFile line in `deployments/systemd/cf-sync.service` (and the deployed unit) to reference `/etc/security-automation/secrets/cloudflare_api_token`. The wizard path is the canonical path per docs; the systemd line is wrong.

---

### F2: Wizard Settings Are Write-Only

**Severity:** CRITICAL
**Location:**
- Wizard writes: `internal/ui/setup_wizard.go` (steps 3, 4, 9)
- Runtime reads: `cmd/cf-sync/ui_runtime.go`

**Observed:**
The wizard writes these keys to the `ui_settings` SQLite table:

| Key | Written In | Step |
|-----|-----------|------|
| `ui_addr` | `setup_wizard.go` | Step 3 |
| `cf_token_path` | `setup_wizard.go` | Step 4 |
| `cf_zone_id` | `setup_wizard.go` | Step 4 |
| `dry_run` | `setup_wizard.go` | Step 9 |
| `mutations_enabled` | `setup_wizard.go` | Step 9 |

`GetSetting` is called in the following locations across the entire codebase:
- `internal/ui/setup_wizard.go:222` — reads `ui_addr` for display in the step 3 form (read-only)
- `internal/ui/setup_wizard.go:630` — reads `ui_addr` for step 8 summary display (read-only)
- `internal/ui/setup_wizard.go:636` — reads `cf_token_path` for step 8 summary display (read-only)
- Tests only (no production runtime path reads these values)

`runUI` in `cmd/cf-sync/ui_runtime.go:122` binds `cfg.UI.Addr` from the YAML/env config and never reads `ui_addr` from SQLite. `cfg.UI.MutationsEnabled` is similarly taken from YAML/env only.

**Expected:**
After the operator completes the wizard and restarts the service, the runtime should apply the wizard's settings as overrides on top of the file-based config, consistent with the config precedence documented in `docs/INSTALL_LAYOUT.md`:
> 4. SQLite UI settings (`ui_settings` table — applied at runtime, not at startup)

**Impact:**
- The UI bind address from step 3 is ignored after restart. The service binds its original YAML/env address.
- `mutations_enabled=true` from step 9 is never applied. The service stays in dry-run mode indefinitely regardless of what the operator confirmed in the wizard.
- `cf_zone_id` is stored but never passed to the daemon — CF syncs would fail even if the token were loaded correctly (see F1).
- The wizard gives the operator false confidence that the system is configured.

**Fix:** Phase 1 — In `cmd/cf-sync/ui_runtime.go`, after `setupStore` is initialized, read `ui_addr` and `mutations_enabled` from SQLite and apply them as overrides before `ui.NewServer` is called. Full fix specification is in `WIZARD_RUNTIME_INTEGRATION_REPORT.md`.

---

### F3: Deployed Systemd Unit Diverged from Repo Template

**Severity:** HIGH
**Location:**
- Repo template: `deployments/systemd/cf-sync.service`
- Live deployed: `/etc/systemd/system/cf-sync.service`

**Observed:**

Key divergences between the repo template and the live unit:

| Field | Repo Template | Live Deployed |
|-------|--------------|---------------|
| `User` | `DynamicUser=yes` | `User=root` / `Group=root` |
| `ExecStart` | `-mode daemon -interval 1m` | `-mode daemon -config /etc/security-automation-go/cf-shadow.yaml -metrics-addr 127.0.0.1:9091` |
| `EnvironmentFile` (primary) | `-/etc/security-automation/security-automation.env` (optional) | `/etc/security-automation-go/cf-shadow.env` (REQUIRED, legacy path) |
| `EnvironmentFile` (secret) | _(not present)_ | `/etc/security-automation/secrets/cf_sync_api_token.env` |
| `StartLimitIntervalSec` | _(not present in [Service])_ | `StartLimitIntervalSec=300` in `[Service]` (wrong section) |
| `ReadWritePaths` | _(correct set)_ | Missing `/etc/security-automation/secrets`, `/etc/security-automation/runtime` |

**Expected:**
The live deployed unit should match the repo template (with environment-specific additions in the correct places), so that changes to the repo are deployable via `sudo cp`.

**Impact:**
Changes to `deployments/systemd/cf-sync.service` have no effect on the running system. The deployed unit references legacy paths (F4) and runs as root. Any documentation that references the repo template is inaccurate for the live system.

**Fix:** Phase 2 — Update the repo template to incorporate the correct EnvironmentFile paths and missing `ReadWritePaths` entries. After update, apply to disk with `sudo cp deployments/systemd/cf-sync.service /etc/systemd/system/cf-sync.service && sudo systemctl daemon-reload`. DynamicUser vs root is out of scope for this sprint (see F3 note below).

**Note — DynamicUser vs root:** The `DynamicUser=yes` vs `User=root` divergence is explicitly out of scope for V1.2. Switching security profiles requires separate testing of filesystem permissions across all paths the service writes to. This will be addressed in a dedicated security hardening sprint.

---

### F4: Legacy Config Hierarchy Still Active

**Severity:** HIGH
**Location:**
- `/etc/security-automation-go/cf-shadow.yaml` — live config file, `service_name: cf-shadow`
- `/etc/security-automation-go/cf-shadow.env` — loaded as REQUIRED EnvironmentFile
- `/etc/crowdsec/cf-sync.env` — Python daemon's legacy CF env (also contains a revoked token)
- Target canonical path: `/etc/security-automation/`

**Observed:**
The live systemd unit (F3) passes `-config /etc/security-automation-go/cf-shadow.yaml` to the daemon. This is the legacy path from a previous naming scheme (`security-automation-go`, `cf-shadow`). The canonical install layout documented in `docs/INSTALL_LAYOUT.md` uses `/etc/security-automation/` without the `-go` suffix. Additionally, `/etc/crowdsec/cf-sync.env` is a remnant of the Python predecessor daemon and contains a revoked Cloudflare token.

**Expected:**
All active configuration files should live under `/etc/security-automation/`. The legacy `/etc/security-automation-go/` directory should be migrated and then deprecated.

**Impact:**
Two parallel config hierarchies exist on disk. The legacy hierarchy takes precedence for the running daemon (loaded first via ExecStart `-config` flag). Any operator editing `/etc/security-automation/` is editing the wrong tree for the currently running service. The revoked token in `/etc/crowdsec/cf-sync.env` poses no active risk (it is not referenced by the Go daemon) but is a credential hygiene issue.

**Fix:** Phase 2 — Execute the migration plan documented in `CONFIGURATION_MIGRATION_PLAN.md`. After migration, `/etc/security-automation-go/` should be archived and removed.

---

### F5: No Systemd Unit for UI Mode

**Severity:** HIGH
**Location:**
- `/etc/systemd/system/cf-sync.service` — runs `-mode daemon` only
- `docs/FIRST_BOOT.md` — instructs `sudo systemctl start cf-sync` then browse to `http://127.0.0.1:9091/`

**Observed:**
The cf-sync binary has two modes:
- `-mode daemon` — background sync daemon (no HTTP)
- `-mode ui` — setup wizard and management web server (HTTP on port 9091)

The deployed systemd unit runs `-mode daemon`. There is no `cf-sync-ui.service` or equivalent unit. The daemon mode does not serve HTTP; port 9091 in the live unit's `ExecStart` is passed as `-metrics-addr`, not as the UI address.

`docs/FIRST_BOOT.md` instructs the operator to:
1. `sudo systemctl start cf-sync`
2. Open a browser to `http://127.0.0.1:9091/`

Step 2 will fail — the daemon is running, not the UI server.

**Expected:**
Either a separate `cf-sync-ui.service` unit exists for the UI mode, or `FIRST_BOOT.md` must document the correct operator-invoked command to run the UI manually.

**Impact:**
First-boot setup is broken as documented. An operator following `FIRST_BOOT.md` will run `systemctl start cf-sync` and then be unable to access the wizard. Without completing the wizard, secrets are never written and the daemon cannot authenticate to Cloudflare.

**Fix:** Phase 1 — Update `docs/FIRST_BOOT.md` to document the correct procedure. The recommended approach is a separate `cf-sync-ui.service` unit (one-shot, or manually started by operator for setup). See `SYSTEMD_CONSOLIDATION_REPORT.md` for the unit design.

---

### F6: `StartLimitIntervalSec` in Wrong Systemd Section

**Severity:** LOW
**Location:** `/etc/systemd/system/cf-sync.service`, `[Service]` section

**Observed:**
```ini
[Service]
StartLimitIntervalSec=300
StartLimitBurst=5
```

**Expected:**
Per the systemd specification, `StartLimitIntervalSec` and `StartLimitBurst` belong in `[Unit]`, not `[Service]`. Placing them in `[Service]` generates a warning in `journalctl -xe` and behavior is systemd-version-dependent (some versions silently ignore them in `[Service]`, others honor them).

**Impact:**
Low — the service may not enforce start rate limiting as intended on some systemd versions. Generates log noise.

**Fix:** Phase 2 — Move these directives to the `[Unit]` section in the repo template and deployed unit.

---

### F7: `ReadWritePaths` Missing Secrets and Runtime Directories

**Severity:** MEDIUM
**Location:** `/etc/systemd/system/cf-sync.service`, `[Service]` section

**Observed:**
```ini
ReadWritePaths=/var/lib/cf-sync /var/log/crowdsec /var/log/security-automation
```

Missing paths that the UI mode writes to:
- `/etc/security-automation/secrets` — wizard writes token files here (steps 4–7)
- `/etc/security-automation/runtime` — wizard writes initial admin password here (step 1)

**Expected:**
All directories the service writes to must be listed in `ReadWritePaths` when `ProtectSystem=strict` or similar sandboxing is active.

**Impact:**
If `ProtectSystem=strict` is enforced (it is referenced in the repo template), the wizard will fail to write secret files. The service will appear to complete wizard steps but files will not be persisted, causing silent failures identical to F1 in effect.

**Fix:** Phase 2 — Add the missing paths to `ReadWritePaths` in both the repo template and the deployed unit.

---

## No Issues Found

The following were verified correct during this audit and require no changes:

**F8 — DefaultEnvFile path is correct:**
`internal/config/envfile.go:11` defines `DefaultEnvFile = "/etc/security-automation/security-automation.env"`. This matches the optional `EnvironmentFile` in the repo template. No mismatch.

**F9 — Compiled config defaults are correct:**
All `DefaultConfig()` paths in `internal/config/config.go` use the `/etc/security-automation/` prefix, matching the canonical install layout in `docs/INSTALL_LAYOUT.md`.

**F10 — AI provider secrets are written and loaded correctly:**
The wizard writes AI provider keys to `/etc/security-automation/secrets/{openai,anthropic,gemini}_api_key`. These match the const paths in `setup_wizard.go` (`openAISecretPath`, `anthropicSecretPath`, `geminiSecretPath`) and the daemon loads them via `ai.Config.{OpenAI,Anthropic,Gemini}.APIKeyFile` — correct path-based loading, not env-var loading. The `WriteSecretFile` function uses tmp+rename+chmod 0600 (atomic write). No issues.

**Atomic write pattern (correct for all secrets):**
`WriteSecretFile` in the wizard creates a temp file, writes the value, syncs, closes, and renames atomically. Mode 0600 is enforced. This pattern is correct and consistent across all secrets the wizard writes.

---

## Canonical vs Actual Secret Loading Paths

| Secret | Wizard Writes To | Daemon Reads From | Match? |
|--------|-----------------|-------------------|--------|
| CF API Token | `/etc/security-automation/secrets/cloudflare_api_token` | `/etc/security-automation/secrets/cf_sync_api_token.env` (EnvironmentFile) | ❌ MISMATCH (F1) |
| AbuseIPDB Key | `/etc/security-automation/secrets/abuseipdb_api_key` | `ABUSEIPDB_KEY` env var via EnvironmentFile | ✓ |
| BetterStack Token | `/etc/security-automation/secrets/betterstack_source_token` | `BETTERSTACK_SOURCE_TOKEN` env var via EnvironmentFile | ✓ |
| OpenAI Key | `/etc/security-automation/secrets/openai_api_key` | `AI_PROVIDER_OPENAI_API_KEY_FILE` → file path | ✓ |
| Anthropic Key | `/etc/security-automation/secrets/anthropic_api_key` | `AI_PROVIDER_ANTHROPIC_API_KEY_FILE` → file path | ✓ |
| Gemini Key | `/etc/security-automation/secrets/gemini_api_key` | `AI_PROVIDER_GEMINI_API_KEY_FILE` → file path | ✓ |
| Admin Password | `/etc/security-automation/secrets/admin_password` | `cfg.UI.AdminPasswordFile` (default matches) | ✓ |
| Initial Password | `/etc/security-automation/runtime/initial-admin-password` | `cfg.UI.InitialPasswordFile` (default matches) | ✓ |

---

## Resolution Matrix

| Finding | Phase | Change Type | Files Affected |
|---------|-------|-------------|----------------|
| F1: CF token filename | Phase 1 | Config (systemd EnvironmentFile line) | `deployments/systemd/cf-sync.service`, `/etc/systemd/system/cf-sync.service` |
| F2: Wizard settings write-only | Phase 1 | Code (ui_runtime.go SQLite reads) | `cmd/cf-sync/ui_runtime.go` |
| F5: No UI mode systemd unit | Phase 1 | Doc + new unit file | `docs/FIRST_BOOT.md`, `deployments/systemd/cf-sync-ui.service` (new) |
| F3: Deployed unit diverged | Phase 2 | Config (systemd template) | `deployments/systemd/cf-sync.service`, `/etc/systemd/system/cf-sync.service` |
| F4: Legacy config active | Phase 2 | Ops (file migration + cleanup) | `/etc/security-automation-go/` → `/etc/security-automation/` |
| F7: ReadWritePaths incomplete | Phase 2 | Config (systemd) | `deployments/systemd/cf-sync.service`, `/etc/systemd/system/cf-sync.service` |
| F6: StartLimitIntervalSec section | Phase 2 | Config (systemd section) | `deployments/systemd/cf-sync.service`, `/etc/systemd/system/cf-sync.service` |
| F8/F9/F10: No issues | — | No action | — |

**Phase 1** = V1.2 sprint blocker — must be resolved before v1.2 release
**Phase 2** = V1.2 hygiene — addressed in the same sprint but not release blockers
