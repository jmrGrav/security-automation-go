# Configuration Migration Plan

**Date:** 2026-06-06
**Sprint:** V1.2 Configuration Consolidation
**Purpose:** Migrate from the legacy `/etc/security-automation-go/` config hierarchy to the canonical `/etc/security-automation/` layout, and clean up the legacy `/etc/crowdsec/cf-sync.env` remnant.

---

## Problem Statement

Two parallel configuration hierarchies exist on disk. The running daemon is pointed at the legacy tree via the systemd `ExecStart -config` flag and a REQUIRED `EnvironmentFile` at the legacy path. The canonical tree (per `docs/INSTALL_LAYOUT.md`) is `/etc/security-automation/`, but active files that override it live under the deprecated `/etc/security-automation-go/` prefix.

Operators editing `/etc/security-automation/` are editing the wrong tree for the currently running service.

---

## Current Layout vs Target Layout

### Current (Legacy — Active)

```
/etc/security-automation-go/
├── cf-shadow.yaml          # Active daemon config (service_name: cf-shadow)
└── cf-shadow.env           # REQUIRED EnvironmentFile loaded by live systemd unit

/etc/crowdsec/
└── cf-sync.env             # Python daemon legacy CF env — contains a revoked token

/etc/security-automation/
├── security-automation.env  # Optional env overrides (correct, but lower precedence)
├── secrets/
│   ├── cloudflare_api_token # Written by wizard (step 4) — NOT loaded by daemon (F1)
│   ├── abuseipdb_api_key
│   ├── betterstack_source_token
│   ├── openai_api_key
│   ├── anthropic_api_key
│   ├── gemini_api_key
│   └── admin_password
└── runtime/
    └── initial-admin-password
```

### Target (Canonical — After Migration)

```
/etc/security-automation/
├── security-automation.env  # General env overrides (optional)
├── secrets/
│   ├── cloudflare_api_token # CF_API_TOKEN=<value> (0600) — written by wizard AND loaded by daemon
│   ├── abuseipdb_api_key    # ABUSEIPDB_KEY=<value> (0600)
│   ├── betterstack_source_token  # BETTERSTACK_SOURCE_TOKEN=<value> (0600)
│   ├── openai_api_key
│   ├── anthropic_api_key
│   ├── gemini_api_key
│   └── admin_password
└── runtime/
    └── initial-admin-password

/var/lib/cf-sync/<scope-id>/
├── runtime.db
├── security-automation-go.pid
└── ui-audit.log

# Deprecated — archived and removed after migration:
# /etc/security-automation-go/  (archived to /etc/security-automation-go.bak/)
# /etc/crowdsec/cf-sync.env     (revoked token — deleted)
```

---

## Config Precedence (Canonical)

From lowest to highest priority after migration:

1. Compiled defaults (`internal/config/config.go` — `DefaultConfig()`)
2. YAML file (`/etc/security-automation/security-automation.yaml`, if `-config` is removed from ExecStart)
3. Environment variables (`/etc/security-automation/security-automation.env`, EnvironmentFile entries)
4. SQLite UI settings (`ui_settings` table — applied at runtime startup after F2 fix)

The live unit currently uses `-config /etc/security-automation-go/cf-shadow.yaml` (step 2 above). After migration this flag is removed; the daemon uses compiled defaults and env-file overrides only.

---

## Migration Steps

### Pre-Migration Checks

Before starting, verify the current state:

```bash
# Confirm the daemon is running from the legacy config
sudo systemctl cat cf-sync | grep -E 'ExecStart|EnvironmentFile'

# Confirm the CF token in the legacy env file
sudo grep CF_API_TOKEN /etc/security-automation-go/cf-shadow.env

# Confirm the canonical secrets directory exists
ls -la /etc/security-automation/secrets/

# Verify the canonical cloudflare_api_token file exists (written by wizard)
sudo ls -la /etc/security-automation/secrets/cloudflare_api_token
```

### Step 1: Stop the Service

```bash
sudo systemctl stop cf-sync
```

Verify it has stopped:

```bash
sudo systemctl is-active cf-sync   # should print: inactive
```

### Step 2: Migrate Config Values

Extract values from the legacy YAML into environment variables in the canonical env file:

```bash
# Read the legacy YAML to identify any non-default values
sudo cat /etc/security-automation-go/cf-shadow.yaml
```

Any non-default values in `cf-shadow.yaml` must be either:
- Moved to `/etc/security-automation/security-automation.env` as environment variable overrides, OR
- Accepted as compiled defaults (if they match `DefaultConfig()`)

The `service_name: cf-shadow` field in the YAML is a legacy artifact. The canonical service name is `cf-sync`.

### Step 3: Migrate the CF API Token

If the canonical `cloudflare_api_token` file does not exist or is empty, copy the token from the legacy env file:

```bash
# Check if the wizard has already written the token
sudo cat /etc/security-automation/secrets/cloudflare_api_token 2>/dev/null || echo "NOT FOUND"

# If not found, extract from legacy env and write canonically
LEGACY_TOKEN=$(sudo grep '^CF_API_TOKEN=' /etc/security-automation-go/cf-shadow.env | cut -d= -f2-)
if [ -n "$LEGACY_TOKEN" ]; then
    echo "CF_API_TOKEN=${LEGACY_TOKEN}" | sudo tee /tmp/cf_token_migration > /dev/null
    sudo cp /tmp/cf_token_migration /etc/security-automation/secrets/cloudflare_api_token
    sudo chmod 0600 /etc/security-automation/secrets/cloudflare_api_token
    sudo chown root:root /etc/security-automation/secrets/cloudflare_api_token
    sudo rm /tmp/cf_token_migration
    echo "Token migrated."
else
    echo "ERROR: No token found in legacy env file. Re-run wizard step 4 after migration."
fi
```

### Step 4: Update the Systemd Unit

Apply the updated systemd unit from the repo template (after the template has been updated per `SYSTEMD_CONSOLIDATION_REPORT.md`):

```bash
sudo cp /home/jm/Documents/security-automation-go/deployments/systemd/cf-sync.service \
    /etc/systemd/system/cf-sync.service
sudo systemctl daemon-reload
```

Verify the updated unit no longer references legacy paths:

```bash
sudo systemctl cat cf-sync | grep -E 'ExecStart|EnvironmentFile|config'
# Should NOT contain: cf-shadow, security-automation-go
```

### Step 5: Verify EnvironmentFile References

After the unit update, the EnvironmentFile must reference the canonical path only:

```bash
# The EnvironmentFile for CF token must point to the canonical file
sudo systemctl cat cf-sync | grep cloudflare
# Expected: EnvironmentFile=-/etc/security-automation/secrets/cloudflare_api_token
# (note the - prefix making it optional, consistent with the token being provided by wizard)
```

### Step 6: Start the Service and Verify

```bash
sudo systemctl start cf-sync
sudo systemctl status cf-sync

# Confirm the service loaded the CF token
sudo journalctl -u cf-sync --since "1 minute ago" | grep -iE 'token|cloudflare|error|fatal'
```

### Step 7: Archive Legacy Files

After confirming the service runs correctly for at least 15 minutes:

```bash
# Archive the legacy directory (do not delete immediately)
sudo mv /etc/security-automation-go /etc/security-automation-go.bak
sudo chmod 000 /etc/security-automation-go.bak   # prevent accidental reads

# Remove the revoked token from crowdsec directory
# First confirm it is truly revoked (not in use by any service)
sudo grep -r cf-sync.env /etc/systemd/ /etc/cron* 2>/dev/null || true
sudo rm /etc/crowdsec/cf-sync.env
```

### Step 8: Final Verification

```bash
# Service is active
sudo systemctl is-active cf-sync

# No references to legacy paths remain in active systemd units
sudo systemctl cat cf-sync | grep 'security-automation-go' && echo "LEGACY PATH FOUND — INVESTIGATE" || echo "OK"

# Canonical secrets are present and correctly permissioned
sudo ls -la /etc/security-automation/secrets/
# All files should be mode 0600, owned by root or the service user

# CF sync is working (check for successful sync log entries)
sudo journalctl -u cf-sync --since "10 minutes ago" | grep -iE 'sync|cloudflare|ban'
```

---

## Backward Compatibility Rules

1. **Keep the archive for 30 days.** Do not delete `/etc/security-automation-go.bak` until after the v1.2 release is confirmed stable.
2. **Do not symlink.** Do not create symlinks from the old path to the new path — this obscures which config is active and defeats the purpose of the migration.
3. **AbuseIPDB and BetterStack secrets.** These are in the canonical directory already. No migration needed. Verify they are present:
   ```bash
   sudo ls /etc/security-automation/secrets/abuseipdb_api_key 2>/dev/null && echo "OK" || echo "Not configured (optional)"
   sudo ls /etc/security-automation/secrets/betterstack_source_token 2>/dev/null && echo "OK" || echo "Not configured (optional)"
   ```
4. **AI provider secrets.** Already in canonical directory. No migration needed.

---

## What to Do with Legacy Files After Migration

| File | Action | Reason |
|------|--------|--------|
| `/etc/security-automation-go/cf-shadow.yaml` | Archive (in `.bak` dir), then delete after 30 days | Superseded by canonical layout |
| `/etc/security-automation-go/cf-shadow.env` | Archive, then delete after 30 days | Token now in canonical path |
| `/etc/crowdsec/cf-sync.env` | Delete immediately | Revoked token; Python daemon is retired |
| `/etc/security-automation-go.bak/` | Delete 30 days post-migration | Safety archive |

---

## Deprecation Timeline

| Date | Action |
|------|--------|
| V1.2 sprint (now) | Execute migration; legacy dir archived |
| V1.2 release | Announce: `/etc/security-automation-go/` is deprecated |
| +30 days | Delete `/etc/security-automation-go.bak/` |
| V1.3+ | Remove any remaining references to `cf-shadow` from docs |

---

## Rollback Procedure

If the migration causes the service to fail and the issue cannot be resolved quickly:

```bash
# Stop service
sudo systemctl stop cf-sync

# Restore legacy directory
sudo mv /etc/security-automation-go.bak /etc/security-automation-go
sudo chmod 755 /etc/security-automation-go

# Restore the original systemd unit (if you have a backup)
sudo cp /etc/systemd/system/cf-sync.service.bak /etc/systemd/system/cf-sync.service
sudo systemctl daemon-reload

# Start service
sudo systemctl start cf-sync
sudo systemctl status cf-sync
```

Always back up the original systemd unit before modifying it:

```bash
sudo cp /etc/systemd/system/cf-sync.service /etc/systemd/system/cf-sync.service.bak
```
