# Recovery Model

**Status:** Current as of v1.6.0  
**Updated:** 2026-06-11

---

## Objective

Document the recovery model that ensures no operator lockout is permanent. An operator who loses their admin password or has a corrupted database can always recover without data loss.

---

## Recovery Scenarios

### Scenario 1: Lost Admin Password

**Symptom:** Login returns 401; the operator does not know the current admin password.

**Recovery:**

```bash
# Step 1: Stop the service
sudo systemctl stop cf-sync

# Step 2: Clear the stored hash from SQLite
sudo sqlite3 /var/lib/security-automation-go/runtime.db \
  "DELETE FROM ui_settings WHERE key='admin_password_hash';"

# Step 3: Restart
sudo systemctl start cf-sync

# Step 4: Navigate to the setup wizard and create a new password
# http://127.0.0.1:9091/setup/step/1
```

**Why this works:** After deleting `admin_password_hash`, `isBootstrapActive()` returns true. The setup wizard at step 1 will prompt for a new administrator password (≥16 chars), hash it with bcrypt, and store it in SQLite. No env vars or flat files are involved.

**Note:** The main CF sync daemon continues running during this procedure. Only the UI server needs to be restarted.

---

### Scenario 2: Corrupted SQLite Database

**Symptom:** `cf-sync -mode ui` fails on startup with a SQLite error; OR login fails with 503 "auth not configured".

**Recovery:**

```bash
# Step 1: Stop the service
sudo systemctl stop cf-sync

# Step 2: Back up the corrupted database
sudo cp /var/lib/security-automation-go/runtime.db \
       /var/lib/security-automation-go/runtime.db.corrupt.$(date +%Y%m%d-%H%M%S)

# Step 3: Remove the corrupted database
sudo rm /var/lib/security-automation-go/runtime.db

# Step 4: Restart — the server creates a fresh database and runs migrations
sudo systemctl start cf-sync

# Step 5: Navigate to the setup wizard and create a new password
# http://127.0.0.1:9091/setup/step/1
```

**Data loss:** Only the UI settings and setup state are lost. All security automation state (decisions log, shadow reports, Cloudflare sync data) is in separate files and unaffected.

---

### Scenario 3: Instance Lock Stuck (Crashed Process)

**Symptom:** `cf-sync -mode ui` fails with "another instance (PID N) is running" but no process with that PID exists.

**Recovery:**

```bash
# Remove the stale lock file
sudo rm /var/lib/security-automation-go/security-automation-go.pid
sudo systemctl start cf-sync
```

**Why this is safe:** The PID file contains the PID of the last owner. If that PID is no longer alive, the lock is stale.

---

### Scenario 4: Session Tokens Invalidated (Server Restart)

**Symptom:** After restart, all active sessions are invalid; browser redirects to login.

**Recovery:** Log in again. This is expected behavior — sessions are in-memory only (intentional, no persistent session store).

---

## No-Lockout Guarantees

| Risk | Guarantee | Mechanism |
|------|-----------|-----------|
| Lost admin password | Always recoverable | SQLite DELETE + wizard step 1 sets new password |
| Corrupted database | Full reset possible | Delete runtime.db, restart, re-run wizard |
| Stale PID lock | Removable | Delete .pid file |
| Expired sessions | Re-login works | Sessions are stateless after restart |

The only unrecoverable scenario is: loss of the underlying filesystem containing `/var/lib/security-automation-go/`. This is covered by standard backup procedures.

---

## Security Considerations

- Recovery procedures require `root` access or membership in the service group
- The new password is set exclusively through the setup wizard — no env vars or flat files are used
- Recovery involves a service restart — the CF sync daemon continues unaffected

---

## Relationship to isBootstrapActive()

```
isBootstrapActive() = true
  → setupStore has no "admin_password_hash" key
  → wizard step 1 is accessible to unauthenticated requests
  → login returns 401 until password is set

Recovery action: set "admin_password_hash" in SQLite
  → via setup wizard step 1 (only supported path)
  → wizard bcrypt-hashes the new password and stores it

isBootstrapActive() = false
  → login accepts the bcrypt-stored password
  → wizard step 1 redirects to /login
```
