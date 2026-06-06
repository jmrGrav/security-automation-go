# Install Layout

The canonical layout for a fresh installation:

```
/etc/security-automation-go/
├── security-automation.env          # General env overrides (optional)
├── secrets/
│   ├── cloudflare_api_token         # CF_API_TOKEN=<value> (0600)
│   ├── abuseipdb_api_key            # ABUSEIPDB_KEY=<value> (0600, optional)
│   ├── betterstack_source_token     # BETTERSTACK_SOURCE_TOKEN=<value> (0600, optional)
│   ├── openai_api_key               # OPENAI_API_KEY=<value> (0600, optional)
│   ├── anthropic_api_key            # ANTHROPIC_API_KEY=<value> (0600, optional)
│   ├── gemini_api_key               # GEMINI_API_KEY=<value> (0600, optional)
│   ├── admin_token                  # Admin API token (0600, optional)
│   └── ui_secret                    # UI session secret (0600, auto-generated)
├── providers/                       # Reserved for future provider config
└── backups/                         # Reserved for config backups

/var/lib/security-automation-go/     # State directory (StateDirectory= in systemd unit)
├── runtime.db                       # SQLite: state, settings, wizard progress, admin_password_hash
├── security-automation-go.pid       # Instance lock
├── ui-audit.log                     # UI action audit log
└── runtime/
    └── initial-admin-password       # One-time bootstrap password (0600, invalidated after setup)

/var/log/security-automation/        # Log directory (LogsDirectory= in systemd unit)
└── startup.log                      # Structured startup diagnostics

/usr/local/bin/cf-sync               # Binary
```

## Config Precedence

From lowest to highest priority:

1. Compiled defaults (in `internal/config/config.go`)
2. YAML file (`-config` flag)
3. Environment variables (`security-automation.env`, EnvironmentFile entries)
4. SQLite UI settings (`ui_settings` table — applied at runtime, not at startup)

## Secret File Permissions

All secret files must be mode **0600** and owned by the service user (or root).
The setup wizard enforces this on every file it writes.
Never chmod these files to world-readable.

## Directories

| Path | Mode | Purpose |
|------|------|---------|
| `/etc/security-automation-go/` | 0755 | Config root |
| `/etc/security-automation-go/secrets/` | 0700 (recommended) | Secret files |
| `/etc/security-automation-go/runtime/` | 0700 (recommended) | Transient runtime files |
| `/var/lib/security-automation-go/` | 0750 | SQLite + state |
| `/var/log/security-automation/` | 0750 | Logs |
