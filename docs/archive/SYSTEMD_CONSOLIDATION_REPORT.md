# Systemd Consolidation Report

**Date:** 2026-06-06
**Sprint:** V1.2 Configuration Consolidation
**Purpose:** Document the divergence between the repo systemd template and the deployed unit, specify required changes, and define the recommended approach for the missing UI mode service.

---

## Problem Statement

The repo template (`deployments/systemd/cf-sync.service`) and the deployed unit (`/etc/systemd/system/cf-sync.service`) have diverged entirely. The deployed unit runs the legacy config, references legacy paths, runs as root, and contains directives in wrong sections. Changes to the repo template have no effect on the live system.

Additionally, there is no systemd unit for `-mode ui` (the setup wizard), making `docs/FIRST_BOOT.md` incorrect.

---

## Diff: Repo Template vs Deployed Unit

### Repo Template (`deployments/systemd/cf-sync.service`)

```ini
[Unit]
Description=cf-sync CrowdSec→Cloudflare ban synchronisation daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
DynamicUser=yes
ExecStart=/usr/local/bin/cf-sync -mode daemon -interval 1m
Restart=on-failure
RestartSec=10s
StateDirectory=cf-sync
LogsDirectory=security-automation
EnvironmentFile=-/etc/security-automation/security-automation.env

ReadWritePaths=/var/lib/cf-sync /var/log/crowdsec /var/log/security-automation

[Install]
WantedBy=multi-user.target
```

### Live Deployed Unit (`/etc/systemd/system/cf-sync.service`)

```ini
[Unit]
Description=cf-sync CrowdSec→Cloudflare ban synchronisation daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/cf-sync -mode daemon -config /etc/security-automation-go/cf-shadow.yaml -metrics-addr 127.0.0.1:9091
Restart=on-failure
RestartSec=10s
StartLimitIntervalSec=300
StartLimitBurst=5
StateDirectory=cf-sync
LogsDirectory=security-automation
EnvironmentFile=/etc/security-automation-go/cf-shadow.env
EnvironmentFile=/etc/security-automation/secrets/cf_sync_api_token.env
EnvironmentFile=-/etc/security-automation/security-automation.env

ReadWritePaths=/var/lib/cf-sync /var/log/crowdsec /var/log/security-automation

[Install]
WantedBy=multi-user.target
```

---

## Line-by-Line Change Analysis

### Changes Required in This Sprint (Phase 2)

#### 1. Remove `-config` flag from `ExecStart`

```ini
# BEFORE:
ExecStart=/usr/local/bin/cf-sync -mode daemon -config /etc/security-automation-go/cf-shadow.yaml -metrics-addr 127.0.0.1:9091

# AFTER:
ExecStart=/usr/local/bin/cf-sync -mode daemon -interval 1m
```

**Why:** The `-config` flag points to the legacy YAML (F4). After migration to canonical layout, the daemon uses compiled defaults + environment variables. The `-metrics-addr` flag is removed because metrics listening is not part of the canonical configuration for this sprint (address it explicitly if metrics are needed).

#### 2. Fix CF token EnvironmentFile (Critical — F1)

```ini
# REMOVE entirely (wrong filename):
EnvironmentFile=/etc/security-automation/secrets/cf_sync_api_token.env

# ADD (correct filename, optional with - prefix):
EnvironmentFile=-/etc/security-automation/secrets/cloudflare_api_token
```

**Why:** The wizard writes to `cloudflare_api_token`. The `-` prefix makes it optional — the service starts without a token when the wizard has not yet been run (in dry-run mode).

#### 3. Remove legacy REQUIRED EnvironmentFile

```ini
# REMOVE:
EnvironmentFile=/etc/security-automation-go/cf-shadow.env
```

**Why:** This is a legacy path (F4). After migration it does not exist. It is REQUIRED (no `-` prefix), so if it's missing, the service fails to start.

#### 4. Fix `StartLimitIntervalSec` section (F6)

```ini
# REMOVE from [Service]:
StartLimitIntervalSec=300
StartLimitBurst=5

# ADD to [Unit]:
StartLimitIntervalSec=300
StartLimitBurst=5
```

**Why:** Per systemd specification, start rate limiting directives belong in `[Unit]`, not `[Service]`. Placement in `[Service]` generates warnings and has version-dependent behavior.

#### 5. Add missing `ReadWritePaths` entries (F7)

```ini
# BEFORE:
ReadWritePaths=/var/lib/cf-sync /var/log/crowdsec /var/log/security-automation

# AFTER:
ReadWritePaths=/var/lib/cf-sync /var/log/crowdsec /var/log/security-automation /etc/security-automation/secrets /etc/security-automation/runtime
```

**Why:** The UI mode writes to `/etc/security-automation/secrets/` (wizard steps 4–7) and `/etc/security-automation/runtime/` (initial password). Without these in `ReadWritePaths`, `ProtectSystem=strict` will block writes.

---

### Changes Explicitly Out of Scope (Do Not Touch This Sprint)

#### DynamicUser vs User=root

```ini
# Repo template (not applied this sprint):
DynamicUser=yes

# Deployed unit (remains as-is):
User=root
Group=root
```

**Why this is out of scope:**
Switching from `User=root` to `DynamicUser=yes` changes the effective UID of the process and affects filesystem ownership across all paths the service reads and writes:
- `/var/lib/cf-sync/` — must be owned by the dynamic user
- `/etc/security-automation/secrets/` — must be readable/writable by the dynamic user
- `/var/log/security-automation/` — must be writable

Switching security profiles requires:
1. Pre-migration: `chown` all relevant directories to the dynamic user
2. Testing that no capability (network access, signal handling) is lost
3. Verifying `StateDirectory=cf-sync` creates `/var/lib/cf-sync` with correct ownership automatically

This is a dedicated security hardening task for a future sprint. **Do not merge the DynamicUser change in V1.2.**

---

## Target Repo Template After V1.2 Changes

The final content of `deployments/systemd/cf-sync.service` after V1.2:

```ini
[Unit]
Description=cf-sync CrowdSec→Cloudflare ban synchronisation daemon
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/cf-sync -mode daemon -interval 1m
Restart=on-failure
RestartSec=10s
StateDirectory=cf-sync
LogsDirectory=security-automation
EnvironmentFile=-/etc/security-automation/security-automation.env
EnvironmentFile=-/etc/security-automation/secrets/cloudflare_api_token
ReadWritePaths=/var/lib/cf-sync /var/log/crowdsec /var/log/security-automation /etc/security-automation/secrets /etc/security-automation/runtime

[Install]
WantedBy=multi-user.target
```

Note: `User=root` / `Group=root` is retained (not `DynamicUser=yes`) for this sprint, matching the currently deployed unit. The `DynamicUser` migration is deferred.

---

## Applying the Updated Template to Disk

After the repo template is updated and committed:

```bash
# Backup the current deployed unit
sudo cp /etc/systemd/system/cf-sync.service /etc/systemd/system/cf-sync.service.bak

# Apply the updated template
sudo cp /home/jm/Documents/security-automation-go/deployments/systemd/cf-sync.service \
    /etc/systemd/system/cf-sync.service

# Reload systemd and restart
sudo systemctl daemon-reload
sudo systemctl restart cf-sync

# Verify
sudo systemctl status cf-sync
sudo journalctl -u cf-sync --since "1 minute ago"
```

---

## Missing UI Mode Service (F5)

### Problem

The cf-sync binary requires `-mode ui` to serve the setup wizard. The deployed unit runs `-mode daemon`. There is no unit for `-mode ui`.

`docs/FIRST_BOOT.md` instructs:
```
sudo systemctl start cf-sync
# → then open browser to http://127.0.0.1:9091/
```

This is incorrect. The daemon mode does not serve HTTP on port 9091. The operator will start the daemon and be unable to access the wizard.

### Recommended Fix: Separate `cf-sync-ui.service`

Create `deployments/systemd/cf-sync-ui.service` as a **manually-activated** (not enabled, not socket-activated) service that runs the UI for first-boot setup:

```ini
[Unit]
Description=cf-sync Setup Wizard (first-boot UI)
Documentation=https://github.com/your-org/security-automation-go/blob/main/docs/FIRST_BOOT.md
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/cf-sync -mode ui
Restart=no
StateDirectory=cf-sync
LogsDirectory=security-automation
EnvironmentFile=-/etc/security-automation/security-automation.env
ReadWritePaths=/var/lib/cf-sync /etc/security-automation/secrets /etc/security-automation/runtime

[Install]
# Not installed by default — operator starts manually for setup
# WantedBy= intentionally omitted
```

**Operator workflow (corrected FIRST_BOOT.md):**

```bash
# Start the UI for first-boot setup
sudo systemctl start cf-sync-ui

# Read the initial password
sudo cat /etc/security-automation/runtime/initial-admin-password

# Open the browser (or SSH tunnel if headless)
# http://127.0.0.1:9091/

# After wizard completes, stop the UI service
sudo systemctl stop cf-sync-ui

# Start the daemon (normal operation)
sudo systemctl start cf-sync
sudo systemctl enable cf-sync
```

### Alternative: Operator-Invoked (No New Unit)

If adding a second unit is undesirable for this sprint, update `docs/FIRST_BOOT.md` to document manual invocation:

```bash
# Run the UI directly (as root or service user) for first-boot setup
sudo /usr/local/bin/cf-sync -mode ui &
CF_SYNC_UI_PID=$!

# Read the initial password
sudo cat /etc/security-automation/runtime/initial-admin-password

# Complete the wizard in browser at http://127.0.0.1:9091/

# Stop the UI after wizard completes
sudo kill $CF_SYNC_UI_PID

# Start the daemon
sudo systemctl start cf-sync
sudo systemctl enable cf-sync
```

**Recommendation:** The separate `cf-sync-ui.service` unit is strongly preferred. It provides proper logging via `journalctl -u cf-sync-ui`, clean process management, and matches what operators expect from a systemd-managed service. The manual invocation alternative is acceptable as a temporary fix but should not be the long-term answer.

---

## Summary of All Required Changes

| Change | Sprint Phase | Files |
|--------|-------------|-------|
| Fix EnvironmentFile CF token path | Phase 1 (blocker) | `deployments/systemd/cf-sync.service`, `/etc/systemd/system/cf-sync.service` |
| Add `cf-sync-ui.service` (or fix FIRST_BOOT.md) | Phase 1 (blocker) | `deployments/systemd/cf-sync-ui.service` (new), `docs/FIRST_BOOT.md` |
| Remove legacy `-config` flag from ExecStart | Phase 2 | Both unit files |
| Remove legacy REQUIRED EnvironmentFile | Phase 2 | Both unit files |
| Move StartLimitIntervalSec to [Unit] | Phase 2 | Both unit files |
| Add missing ReadWritePaths entries | Phase 2 | Both unit files |
| DynamicUser migration | Deferred (future sprint) | Both unit files + filesystem chown |
