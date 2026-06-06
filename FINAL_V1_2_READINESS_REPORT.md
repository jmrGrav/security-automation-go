# V1.2 Readiness Report

**Date:** 2026-06-06
**Sprint:** V1.2 Configuration Consolidation
**Status:** PRE-CHECK — Pending code and config fixes

> **Note:** This report will be finalized and marked PASS only after all code fixes, config changes, and migration steps documented in the V1.2 audit documents have been applied and verified. Current status reflects the pre-fix state as of 2026-06-06.

---

## Changes Required Before This Report Can Be Marked PASS

All of the following must be applied, in order:

### Phase 1 (Blockers — must be done first)

1. **[CODE]** `cmd/cf-sync/ui_runtime.go` — add SQLite overrides for `ui_addr` and `mutations_enabled` after `setupStore` initialization (see `WIZARD_RUNTIME_INTEGRATION_REPORT.md` for exact code block)
2. **[CONFIG]** `deployments/systemd/cf-sync.service` — fix `EnvironmentFile` to reference `/etc/security-automation/secrets/cloudflare_api_token` (not `cf_sync_api_token.env`); add `-` prefix to make it optional
3. **[CONFIG]** `/etc/systemd/system/cf-sync.service` — apply the same EnvironmentFile fix to the live deployed unit; reload systemd
4. **[DOC/UNIT]** `docs/FIRST_BOOT.md` — correct the first-boot procedure to reflect that UI mode requires a separate invocation (not `systemctl start cf-sync`)
5. **[NEW FILE]** `deployments/systemd/cf-sync-ui.service` — create the UI mode service unit for first-boot setup (see `SYSTEMD_CONSOLIDATION_REPORT.md`)

### Phase 2 (Hygiene — same sprint, not release blockers)

6. **[OPS]** Execute config migration per `CONFIGURATION_MIGRATION_PLAN.md`: stop service, migrate CF token, update deployed systemd unit, start service, archive `/etc/security-automation-go/`
7. **[OPS]** Delete `/etc/crowdsec/cf-sync.env` (revoked token, no active service references it)
8. **[CONFIG]** `deployments/systemd/cf-sync.service` — move `StartLimitIntervalSec` and `StartLimitBurst` from `[Service]` to `[Unit]`
9. **[CONFIG]** `deployments/systemd/cf-sync.service` — add `/etc/security-automation/secrets` and `/etc/security-automation/runtime` to `ReadWritePaths`
10. **[CONFIG]** `deployments/systemd/cf-sync.service` — remove `-config /etc/security-automation-go/cf-shadow.yaml` and legacy `EnvironmentFile` from `ExecStart` (done as part of migration)

---

## Success Criteria Checklist

| # | Criterion | Phase | Current Status |
|---|-----------|-------|---------------|
| 1 | Wizard-written CF token is loaded by the daemon at startup | Phase 1 | BLOCKED — EnvironmentFile filename mismatch (F1) |
| 2 | Operator-configured UI address from wizard step 3 is applied after restart | Phase 1 | BLOCKED — `runUI` never reads `ui_addr` from SQLite (F2) |
| 3 | `mutations_enabled=true` from wizard step 9 is applied after restart | Phase 1 | BLOCKED — `runUI` never reads `mutations_enabled` from SQLite (F2) |
| 4 | First-boot documentation is accurate and the wizard is reachable | Phase 1 | BLOCKED — no UI mode unit; FIRST_BOOT.md instructs wrong command (F5) |
| 5 | Repo template and deployed systemd unit are in sync | Phase 2 | IN_PROGRESS — diverged; requires migration + template update (F3) |
| 6 | All active config files are under `/etc/security-automation/` | Phase 2 | BLOCKED — legacy `/etc/security-automation-go/` is active (F4) |
| 7 | No revoked or orphaned secrets remain on disk | Phase 2 | BLOCKED — `/etc/crowdsec/cf-sync.env` not yet deleted (F4) |
| 8 | `StartLimitIntervalSec` in correct systemd section | Phase 2 | BLOCKED — in `[Service]`, must move to `[Unit]` (F6) |
| 9 | `ReadWritePaths` covers all directories the service writes to | Phase 2 | BLOCKED — missing `/etc/security-automation/secrets` and `/etc/security-automation/runtime` (F7) |
| 10 | All secrets verified at mode 0600 in canonical locations | Phase 2 | IN_PROGRESS — canonical secrets written correctly; legacy cleanup pending |

---

## Items Already Passing (No Changes Required)

| Item | Evidence |
|------|---------|
| Compiled config defaults use `/etc/security-automation/` prefix | `internal/config/config.go` `DefaultConfig()` verified |
| `DefaultEnvFile` matches systemd optional EnvironmentFile | `internal/config/envfile.go:11` verified |
| AI provider secrets: wizard writes to canonical path, daemon loads via file path | All three const paths and ai.Config loading verified |
| Admin password: wizard writes to canonical path, server loads via `cfg.UI.AdminPasswordFile` | Verified — default path matches |
| Initial password: service generates at canonical path, `cfg.UI.InitialPasswordFile` default matches | Verified |
| `WriteSecretFile` uses atomic tmp+rename+chmod 0600 pattern | Verified — correct for all wizard-written secrets |

---

## Final Sign-Off Checklist

To mark this report PASS, a reviewer must confirm each of the following after fixes are applied:

- [ ] `journalctl -u cf-sync` shows successful CF API authentication at startup (no token error)
- [ ] `systemctl status cf-sync` shows `Active: active (running)` with the updated ExecStart
- [ ] `sudo systemctl cat cf-sync | grep EnvironmentFile` shows `cloudflare_api_token` (not `cf_sync_api_token.env`)
- [ ] `sudo systemctl cat cf-sync | grep 'security-automation-go'` returns nothing (no legacy paths)
- [ ] `sudo systemctl cat cf-sync | grep StartLimit` shows directives in `[Unit]` section
- [ ] `sudo ls /etc/security-automation-go` returns `No such file or directory` or the path is `/etc/security-automation-go.bak` and chmod 000
- [ ] `sudo ls /etc/crowdsec/cf-sync.env` returns `No such file or directory`
- [ ] `sudo ls -la /etc/security-automation/secrets/` shows all files at mode 0600
- [ ] Starting `cf-sync-ui`, completing wizard step 9, restarting the UI, and browsing to the configured address shows the UI is accessible at the step-3 address
- [ ] A new `cf-sync-ui.service` unit exists in `deployments/systemd/` and `docs/FIRST_BOOT.md` references it

---

## Document Cross-References

| Document | Covers |
|---------|--------|
| `ARCHITECTURE_CONSISTENCY_AUDIT.md` | All findings F1–F10 with severity, location, impact |
| `CONFIGURATION_MIGRATION_PLAN.md` | Legacy→canonical migration runbook and script |
| `SECRET_LOADING_MODEL.md` | Canonical secret registry, F1 fix, orphan cleanup |
| `SYSTEMD_CONSOLIDATION_REPORT.md` | Template vs deployed diff, all required unit changes, UI service design |
| `WIZARD_RUNTIME_INTEGRATION_REPORT.md` | F2 root cause, exact code fix for `ui_runtime.go`, dry-run architecture |
| This document | Pre-check status, final sign-off checklist |
