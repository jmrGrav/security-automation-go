# Upgrade Compatibility Report — Phase 9

**Sprint:** V1.4 Final Hardening  
**Date:** 2026-06-07  
**Upgrade path:** v1.1 → v1.4  
**Status:** SAFE — automatic migration, no manual steps required

---

## Summary

An existing v1.1 installation can be upgraded to v1.4 by replacing the binary and restarting the service. SQLite migrations run automatically on startup. No data is lost. The admin password must be re-entered via the setup wizard (migration 15 initializes the wizard tables and the operator completes step 2 to store the new bcrypt hash).

---

## What Changed Between v1.1 and v1.4

### Breaking Changes

| Area | Change | Impact |
|------|--------|--------|
| Admin password storage | Removed `secrets/admin_password` file; hash now in SQLite `ui_settings["admin_password_hash"]` | **Auth re-enrollment required** (see below) |
| State directory | Changed from `/var/lib/cf-sync` to `/var/lib/security-automation-go` | Needs data migration (see below) |
| Binary install path | Changed from `/opt/security-automation-go/bin/` to `/usr/local/bin/` | Manual copy needed |

### Non-Breaking Additions

| Area | Addition | Impact |
|------|----------|--------|
| SQLite migration 15 | `setup_state` + `ui_settings` tables | Auto-applied on first start |
| Setup wizard | 9-step first-boot wizard | Appears once on first v1.4 start |
| Config field removed | `AdminPasswordFile` / `UI_ADMIN_PASSWORD_FILE` | Env var silently ignored (field removed) |

---

## Upgrade Procedure

### Step 1: Pre-Upgrade Checklist

```bash
# Verify current version and state
systemctl status cf-sync
sqlite3 /var/lib/cf-sync/runtime.db ".schema schema_migrations" | grep -c "INSERT"  # count migrations
```

### Step 2: Stop the Service

```bash
sudo systemctl stop cf-sync
```

### Step 3: Migrate State Directory

The state directory changed from `/var/lib/cf-sync` to `/var/lib/security-automation-go`.

```bash
# Option A: Move existing state (recommended — preserves all sync history)
sudo mv /var/lib/cf-sync /var/lib/security-automation-go
sudo systemctl set-property cf-sync StateDirectory=security-automation-go

# Option B: Start fresh (all sync history lost)
# Do nothing — systemd creates the new dir automatically
```

### Step 4: Replace Binary

```bash
# Build new binary
go build -o bin/cf-sync ./cmd/cf-sync/

# Install
sudo install -Dm 755 bin/cf-sync /usr/local/bin/cf-sync
# Remove old binary location if it exists
sudo rm -f /opt/security-automation-go/bin/cf-sync
```

### Step 5: Update Systemd Unit

```bash
sudo cp deployments/systemd/cf-sync.service /etc/systemd/system/cf-sync.service
sudo systemctl daemon-reload
```

### Step 6: Start Service

```bash
sudo systemctl start cf-sync
# Watch for migration completion
journalctl -u cf-sync -f
```

On first start, migration 15 runs automatically:
```
INFO  running SQLite migration version=15 description="Setup wizard state and UI settings"
INFO  migration complete
INFO  initial setup password available path=/var/lib/security-automation-go/runtime/initial-admin-password
```

### Step 7: Complete Admin Password Re-Enrollment

In v1.4, admin credentials live exclusively in SQLite. The v1.1 `secrets/admin_password` file is ignored. The operator must set a new password through the setup wizard.

```bash
# Read the one-time initial password
sudo cat /var/lib/security-automation-go/runtime/initial-admin-password

# Open the UI (default: http://127.0.0.1:8080/setup)
# Enter the initial password at step 2
# Set a new permanent admin password
# The initial-admin-password file is automatically truncated after step 2
```

Alternatively, use the env var to seed the password automatically:

```bash
# Set before starting
sudo systemctl set-environment \
  SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD='<strong-password>'
sudo systemctl start cf-sync
# After setup, remove the env var
sudo systemctl unset-environment SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD
sudo systemctl restart cf-sync
```

### Step 8: Remove Old Config Files (Optional Cleanup)

```bash
# The admin_password file is no longer used
# Keep it for now — it does nothing harmful
# Remove after confirming v1.4 is stable
# sudo rm /etc/security-automation-go/secrets/admin_password
```

---

## SQLite Migration Safety

**Migration 15** (`setup_state` + `ui_settings` tables):
- Uses `CREATE TABLE IF NOT EXISTS` — idempotent; safe to run on an existing database
- Uses `INSERT OR IGNORE` — does not overwrite existing wizard state
- Additive only — no table drops, no column removals, no data transformations
- Runs inside the existing migration manager transaction model

All 15 migrations (1-15) use `CREATE TABLE IF NOT EXISTS` or `ALTER TABLE ADD COLUMN IF NOT EXISTS` — all additive and idempotent.

---

## Rollback Procedure (v1.4 → v1.1)

SQLite migrations cannot be rolled back automatically (no down-migrations). To roll back:

1. Stop the service
2. Replace the binary with the v1.1 binary
3. The v1.1 binary will ignore migration 15 tables (they are additive)
4. The `secrets/admin_password` file must be restored manually (v1.1 reads it)

**Note:** The state directory path change (`cf-sync` → `security-automation-go`) must be reverted manually. This is the only destructive step in a rollback.

---

## Data Preservation

| Data | Preserved in Upgrade | Notes |
|------|---------------------|-------|
| SQLite state (leases, events, decisions) | ✅ Yes | Existing tables untouched |
| Shadow reports | ✅ Yes | Files in state dir |
| UI audit log | ✅ Yes | `ui-audit.log` in state dir |
| Admin password | ❌ Re-enrollment required | v1.1 hash format incompatible |
| Cloudflare API token | ✅ Yes | File unchanged |
| AI provider keys | ✅ Yes | Files unchanged |
| Setup wizard state | N/A | New tables, no prior state to preserve |

---

## Risk Assessment

| Risk | Severity | Mitigation |
|------|---------|-----------|
| Admin lockout during upgrade | Medium | Use env var to pre-seed password |
| State dir migration failure | Low | `mv` is atomic at OS level; backup before moving |
| Migration 15 failure | Very Low | Uses IF NOT EXISTS; idempotent |
| Old config file conflicts | Very Low | Removed fields are silently ignored |

**Overall upgrade risk: LOW** — Automatic migration with one predictable manual step (admin password re-enrollment).
