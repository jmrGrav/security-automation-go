# Recovery Model — Phase 7

**Sprint:** V1.4 Final Hardening  
**Date:** 2026-06-07  
**Status:** COMPLETE

---

## Objective

Document the recovery model that ensures no operator lockout is permanent. An operator who loses their admin password, loses the initial-password file, or has a corrupted database can always recover without data loss and without stopping the main daemon.

---

## Recovery Scenarios

### Scenario 1: Lost Admin Password (Normal Operation)

**Symptom:** Login returns 401; the operator does not know the current admin password.

**Recovery:**

```bash
# Step 1: Stop the UI server
sudo systemctl stop cf-sync

# Step 2: Clear the stored hash from SQLite
sudo sqlite3 /var/lib/security-automation-go/ui_settings.db \
  "DELETE FROM ui_settings WHERE key='admin_password_hash';"

# Step 3: Optionally set a new initial password via the env var
# (or let the wizard generate a new one from the initial-admin-password file)
sudo systemctl set-environment \
  SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD='<new-strong-password>'

# Step 4: Restart
sudo systemctl start cf-sync

# Step 5: If using env var: log in with the new password and remove the env var
# If not: read the initial password from:
sudo cat /var/lib/security-automation-go/runtime/initial-admin-password
```

**Why this works:** After deleting `admin_password_hash` from SQLite, `isBootstrapActive()` returns true, and the next login attempt will be redirected to the password change flow using the initial-admin-password file or the env var seed.

**Note:** The main CF sync daemon continues running during this procedure. Only the UI server needs to be restarted.

---

### Scenario 2: Lost Initial Password File

**Symptom:** Setup wizard at step 2 but the `runtime/initial-admin-password` file was deleted or truncated.

**Recovery:**

```bash
# Option A: Re-generate the initial password by restarting the UI server
# (GenerateInitialPassword is idempotent — if the file is gone, it creates a new one)
sudo systemctl restart cf-sync
sudo cat /var/lib/security-automation-go/runtime/initial-admin-password

# Option B: Set password via env var (skips the file entirely)
sudo systemctl set-environment \
  SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD='<new-strong-password>'
sudo systemctl restart cf-sync
# Log in with the new password, then unset the env var
sudo systemctl unset-environment SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD
sudo systemctl restart cf-sync
```

**Why this works:** `GenerateInitialPassword` creates a new file if absent. Alternatively, the env var seeds SQLite directly and bypasses the file mechanism entirely.

---

### Scenario 3: Corrupted SQLite Database

**Symptom:** `cf-sync -mode ui` fails on startup with a SQLite error; OR login fails with 503 "auth not configured".

**Recovery:**

```bash
# Step 1: Stop the UI server
sudo systemctl stop cf-sync

# Step 2: Back up the corrupted database
sudo cp /var/lib/security-automation-go/runtime.db \
       /var/lib/security-automation-go/runtime.db.corrupt.$(date +%Y%m%d-%H%M%S)

# Step 3: Remove the corrupted database
sudo rm /var/lib/security-automation-go/runtime.db

# Step 4: Restart — the server will create a fresh database and re-run migrations
sudo systemctl start cf-sync

# Step 5: Complete the setup wizard again with a new admin password
sudo cat /var/lib/security-automation-go/runtime/initial-admin-password
```

**Data loss:** Only the UI settings and setup state are lost. All security automation state (decisions log, shadow reports, Cloudflare sync data) is in separate files and unaffected.

**Note:** For scope-specific databases (e.g., `zone-123/runtime.db`), only replace the affected scope's database.

---

### Scenario 4: Instance Lock Stuck (Crashed Process)

**Symptom:** `cf-sync -mode ui` fails with "another instance (PID N) is running" but no process with that PID exists.

**Recovery:**

```bash
# Remove the stale lock file
sudo rm /var/lib/security-automation-go/security-automation-go.pid
sudo systemctl start cf-sync
```

**Why this is safe:** The PID file contains the PID of the last owner. If that PID is no longer alive, the lock is stale.

---

### Scenario 5: Session Tokens Invalidated (Server Restart)

**Symptom:** After restart, all active sessions are invalid; browser redirects to login.

**Recovery:** Log in again. This is expected behavior — sessions are in-memory only (intentional, no persistent session store).

---

## No-Lockout Guarantees

| Risk | Guarantee | Mechanism |
|------|-----------|-----------|
| Lost admin password | Always recoverable | SQLite DELETE + env var or file restart |
| Lost initial password | Always recoverable | GenerateInitialPassword creates a new one |
| Corrupted database | Full reset possible | Delete runtime.db, restart |
| Stale PID lock | Removable | Delete .pid file |
| Expired sessions | Re-login works | Sessions are stateless after restart |

The only unrecoverable scenario is: loss of the underlying filesystem containing `/var/lib/security-automation-go/`. This is covered by standard backup procedures.

---

## Security Considerations

- Recovery procedures require `root` access or membership in the service group
- The `SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD` env var seeds SQLite but is never logged
- Recovery involves a service restart — the CF sync daemon continues unaffected
- After recovery, remove the env var and rotate the admin password via the UI

---

## Relationship to isBootstrapActive()

```
isBootstrapActive() = true
  → setupStore has no "admin_password_hash" key
  → login returns 401
  → authenticated requests redirect to /ui/settings/password/change

Recovery action: set "admin_password_hash" in SQLite
  → via setup wizard (normal flow)
  → via SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD env var (automated)
  → via DELETE + restart (emergency reset)
```
