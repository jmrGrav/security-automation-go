# V1.2 Readiness Report

**Date:** 2026-06-06
**Sprint:** V1.2 Configuration Consolidation
**Status:** PARTIAL — Code fixes applied; operational migration pending

---

## What Was Fixed This Sprint

### Code Fixes (commit `07d0770`)

| Fix | File | Change |
|-----|------|--------|
| CF token path alignment | `internal/ui/setup_wizard.go` | `cfTokenSecretPath` → `cf_sync_api_token.env` (matches systemd EnvironmentFile) |
| Wizard settings applied at runtime | `cmd/cf-sync/ui_runtime.go` | `ui_addr` and `mutations_enabled` from SQLite applied to cfg before server bind |
| Systemd template: StartLimit placement | `deployments/systemd/cf-sync.service` | Moved `StartLimitIntervalSec` / `StartLimitBurst` from `[Service]` to `[Unit]` |
| Systemd template: EnvironmentFile | `deployments/systemd/cf-sync.service` | Added `EnvironmentFile=/etc/security-automation/secrets/cf_sync_api_token.env` |
| Systemd template: ReadWritePaths | `deployments/systemd/cf-sync.service` | Added `/etc/security-automation/secrets` and `/etc/security-automation/runtime` |
| Systemd template: Wants | `deployments/systemd/cf-sync.service` | Added `Wants=network.target` to `[Unit]` |
| First-boot documentation | `docs/FIRST_BOOT.md` | Added "Starting the UI" section explaining `-mode ui` invocation |

---

## Success Criteria Checklist

| # | Criterion | Status | Evidence |
|---|-----------|--------|---------|
| 1 | One canonical configuration layout | ✅ IN REPO — ⏸ PENDING OPS | Config defaults use `/etc/security-automation/`; live service still loads `/etc/security-automation-go/cf-shadow.yaml` |
| 2 | One canonical secret layout | ✅ CODE FIXED | Wizard now writes to `cf_sync_api_token.env`; all other secrets at canonical paths |
| 3 | Wizard settings actually used by runtime | ✅ CODE FIXED | `ui_addr` + `mutations_enabled` applied from SQLite in `runUI` on startup |
| 4 | No hybrid configuration | ⏸ PENDING OPS | Legacy `/etc/security-automation-go/` must be migrated; see CONFIGURATION_MIGRATION_PLAN.md |
| 5 | No orphaned secret files | ⏸ PENDING OPS | `/etc/crowdsec/cf-sync.env` (revoked token) still on disk |
| 6 | No ambiguity about active token source | ✅ CODE FIXED | Wizard writes to `cf_sync_api_token.env`; systemd EnvironmentFile loads same file |
| 7 | Service survives reboot | ⏸ PENDING OPS | Repo template updated; live unit not yet replaced |
| 8 | Documentation matches implementation | ✅ FIXED | FIRST_BOOT.md corrected; audit docs written |
| 9 | No new features added | ✅ CONFIRMED | All changes are alignment fixes only |
| 10 | Ready for production cutover afterwards | ⏸ PENDING OPS | Requires CF token rotation + ops migration |

---

## Pending Operational Steps (not code — require root access)

These are not code changes. They must be applied manually by the operator:

### Step 1: Apply new systemd unit to disk

```bash
sudo cp deployments/systemd/cf-sync.service /etc/systemd/system/cf-sync.service
sudo systemctl daemon-reload
```

**Do not restart the service yet** — wait until the config migration (Step 2) is complete.

### Step 2: Migrate config from legacy to canonical path

Follow `CONFIGURATION_MIGRATION_PLAN.md` in full. Summary:

```bash
# Stop daemon
sudo systemctl stop cf-sync

# Create canonical config if not present
sudo cp /etc/security-automation-go/cf-shadow.yaml /etc/security-automation/cf-sync.yaml
# Edit cf-sync.yaml: change service_name from cf-shadow to cf-sync

# Rotate CF API token (required — existing token was revoked)
# Then write the new token:
echo "CF_API_TOKEN=<new-token>" | sudo tee /etc/security-automation/secrets/cf_sync_api_token.env
sudo chmod 0600 /etc/security-automation/secrets/cf_sync_api_token.env

# Update ExecStart in /etc/systemd/system/cf-sync.service:
# ExecStart=/usr/local/bin/cf-sync -mode daemon -config /etc/security-automation/cf-sync.yaml -interval 1m
sudo systemctl daemon-reload

# Start daemon
sudo systemctl start cf-sync
sudo systemctl status cf-sync
```

### Step 3: Clean up legacy files

```bash
# After confirming new config works:
sudo mv /etc/security-automation-go /etc/security-automation-go.bak
sudo rm /etc/crowdsec/cf-sync.env   # revoked token
```

### Step 4: Verify

```bash
journalctl -u cf-sync -n 50 --no-pager
# Expect: successful CF API token verification, no 401 errors
```

---

## Final Sign-Off Checklist

Check each after ops steps are complete:

- [ ] `journalctl -u cf-sync` shows successful CF API authentication (no 401 / token error)
- [ ] `systemctl status cf-sync` shows `Active: active (running)` with `-config /etc/security-automation/cf-sync.yaml`
- [ ] `sudo systemctl cat cf-sync | grep 'security-automation-go'` returns nothing
- [ ] `sudo systemctl cat cf-sync | grep StartLimit` shows directives under `# [Unit]`
- [ ] `sudo ls /etc/security-automation-go` returns not found or only the `.bak` rename
- [ ] `sudo ls /etc/crowdsec/cf-sync.env` returns not found
- [ ] `sudo ls -la /etc/security-automation/secrets/` shows all files at mode 0600
- [ ] Starting `-mode ui`, completing wizard step 9, restarting UI, confirms `mutations_enabled` takes effect

---

## Document Cross-References

| Document | Covers |
|---------|--------|
| `ARCHITECTURE_CONSISTENCY_AUDIT.md` | All findings F1–F10 with severity, location, impact |
| `CONFIGURATION_MIGRATION_PLAN.md` | Legacy→canonical migration runbook and script |
| `SECRET_LOADING_MODEL.md` | Canonical secret registry, CF token path fix |
| `SYSTEMD_CONSOLIDATION_REPORT.md` | Template vs deployed diff, all required unit changes |
| `WIZARD_RUNTIME_INTEGRATION_REPORT.md` | SQLite→runtime settings bridge, exact code fix |
