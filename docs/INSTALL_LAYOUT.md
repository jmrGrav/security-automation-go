# Install Layout

The canonical layout for a fresh installation:

```
/etc/security-automation-go/
└── security-automation.env          # Bootstrap-only non-secret overrides

/var/lib/security-automation-go/     # State directory (StateDirectory= in systemd unit)
├── runtime.db                       # SQLite: state, settings, wizard progress, encrypted credentials
├── security-automation-go.pid       # Instance lock
├── ui-audit.log                     # UI action audit log
├── secret.key                       # Local master key for encrypted credentials (0600)
└── runtime/
    └── initial-admin-password       # One-time bootstrap password for step 2 (0600, invalidated after setup)
    └── ui_secret                    # UI setup secret for step 1 / session secret (0600, auto-generated)

/var/log/security-automation/        # Log directory (LogsDirectory= in systemd unit)
└── startup.log                      # Structured startup diagnostics

/usr/local/bin/cf-sync               # Binary
```

## Config Precedence

From lowest to highest priority:

1. Compiled defaults (in `internal/config/config.go`)
2. YAML file (`-config` flag)
3. Bootstrap env file (`/etc/security-automation-go/security-automation.env`)
4. SQLite settings + encrypted credentials (`ui_settings`, `credential_secrets`) applied at runtime

## Secret File Permissions

Only the local master key and runtime-generated UI files remain on disk.

All runtime secret files must be mode **0600** and owned by `security-automation:security-automation`.
Never chmod these files to world-readable.

## Directories

| Path | Mode | Purpose |
|------|------|---------|
| `/etc/security-automation-go/` | 0755 | Bootstrap config root |
| `/etc/security-automation-go/security-automation.env` | 0644 or 0640 | Bootstrap-only non-secret env |
| `/var/lib/security-automation-go/` | 0750 | SQLite + state |
| `/var/lib/security-automation-go/runtime/` | 0750 | Transient runtime files |
| `/var/log/security-automation/` | 0750 | Logs |
