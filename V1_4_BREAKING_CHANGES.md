# V1.4 Breaking Changes

**Version:** v1.4  
**Date:** 2026-06-06  
**Type:** Breaking change — configuration layout freeze

---

## Summary

Starting with v1.4, the **only** supported configuration root is `/etc/security-automation-go/`.

The path `/etc/security-automation/` is **removed from all code**. No migration helpers, no fallback loaders, no compatibility shims. If an installation uses `/etc/security-automation/`, it must migrate before upgrading to v1.4.

---

## What Changed

### Removed: `/etc/security-automation/` as a valid config root

All code defaults, systemd unit templates, and documentation previously referenced `/etc/security-automation/`. As of v1.4, every reference has been updated to `/etc/security-automation-go/`.

### Removed: `cf_sync_api_token.env` as the Cloudflare token filename

The Cloudflare API token file was previously named `cf_sync_api_token.env` (introduced in v1.2 to match the systemd EnvironmentFile). As of v1.4, the canonical filename is `cloudflare_api_token` (no `.env` suffix), consistent with all other secret files in the v1.4 layout.

Both the setup wizard and the systemd EnvironmentFile now reference `cloudflare_api_token`.

---

## Canonical v1.4 Layout

```
/etc/security-automation-go/
├── security-automation.env          # General env overrides (optional, mode 0600)
├── secrets/
│   ├── cloudflare_api_token         # CF_API_TOKEN=<value>  (0600)
│   ├── admin_token                  # CF_SYNC_API_TOKEN=<value> (0600)
│   ├── ui_secret                    # UI session HMAC key (0600)
│   ├── admin_password               # bcrypt hash of admin UI password (0600)
│   ├── abuseipdb_api_key            # optional (0600)
│   ├── betterstack_source_token     # optional (0600)
│   ├── openai_api_key               # optional (0600)
│   ├── anthropic_api_key            # optional (0600)
│   └── gemini_api_key               # optional (0600)
├── providers/
│   └── ai-providers.env             # Non-secret AI provider state (0640)
├── runtime/
│   └── initial-admin-password       # One-time setup password (0600, truncated after setup)
└── backups/                         # Reserved
```

All secret files: mode **0600**, owner **root:root**, atomic writes (tmp + rename + chmod).

---

## Systemd Unit Changes

| Field | v1.2 value | v1.4 value |
|-------|-----------|-----------|
| `EnvironmentFile` (CF token) | `/etc/security-automation/secrets/cf_sync_api_token.env` | `/etc/security-automation-go/secrets/cloudflare_api_token` |
| `EnvironmentFile` (env) | `-/etc/security-automation/security-automation.env` | `-/etc/security-automation-go/security-automation.env` |
| `ReadWritePaths` | `... /etc/security-automation/secrets /etc/security-automation/runtime` | `... /etc/security-automation-go/secrets /etc/security-automation-go/runtime` |

---

## Code Default Changes

| Location | v1.2 default | v1.4 default |
|----------|-------------|-------------|
| `internal/config/envfile.go` | `/etc/security-automation/security-automation.env` | `/etc/security-automation-go/security-automation.env` |
| `internal/config/config.go` `AdminTokenFile` | `/etc/security-automation/secrets/admin_token` | `/etc/security-automation-go/secrets/admin_token` |
| `internal/config/config.go` `SecretFile` | `/etc/security-automation/secrets/ui_secret` | `/etc/security-automation-go/secrets/ui_secret` |
| `internal/config/config.go` `AdminPasswordFile` | `/etc/security-automation/secrets/admin_password` | `/etc/security-automation-go/secrets/admin_password` |
| `internal/config/config.go` `InitialPasswordFile` | `/etc/security-automation/runtime/initial-admin-password` | `/etc/security-automation-go/runtime/initial-admin-password` |
| `internal/config/config.go` `ProviderStateFile` | `/etc/security-automation/providers/ai-providers.env` | `/etc/security-automation-go/providers/ai-providers.env` |
| `internal/ui/setup_wizard.go` `cfTokenSecretPath` | `/etc/security-automation/secrets/cf_sync_api_token.env` | `/etc/security-automation-go/secrets/cloudflare_api_token` |
| `internal/ui/setup_wizard.go` AI secrets | `/etc/security-automation/secrets/*` | `/etc/security-automation-go/secrets/*` |
| `internal/ui/provider_admin.go` AI secrets | `/etc/security-automation/secrets/*` | `/etc/security-automation-go/secrets/*` |
| `internal/ui/provider_admin.go` install hints | `/etc/security-automation` | `/etc/security-automation-go` |

---

## Migration from v1.2/v1.3

There is no automated migration. The following manual steps are required before starting a v1.4 binary:

1. **Create the new config root:**
   ```bash
   sudo mkdir -p /etc/security-automation-go/{secrets,providers,runtime,backups}
   sudo chmod 700 /etc/security-automation-go/secrets
   sudo chmod 700 /etc/security-automation-go/runtime
   ```

2. **Move or recreate all secret files** with the canonical names:
   ```bash
   # Cloudflare token — rename from cf_sync_api_token.env if it exists
   sudo cp /etc/security-automation/secrets/cf_sync_api_token.env \
     /etc/security-automation-go/secrets/cloudflare_api_token
   sudo chmod 0600 /etc/security-automation-go/secrets/cloudflare_api_token

   # Other secrets — direct copy if present
   for f in admin_token ui_secret admin_password abuseipdb_api_key \
             betterstack_source_token openai_api_key anthropic_api_key gemini_api_key; do
     src="/etc/security-automation/secrets/$f"
     dst="/etc/security-automation-go/secrets/$f"
     [ -f "$src" ] && sudo cp "$src" "$dst" && sudo chmod 0600 "$dst"
   done
   ```

3. **Copy env file** (if it exists):
   ```bash
   sudo cp /etc/security-automation/security-automation.env \
     /etc/security-automation-go/security-automation.env
   sudo chmod 0600 /etc/security-automation-go/security-automation.env
   ```

4. **Update the live systemd unit** to point to the new paths and reload:
   ```bash
   sudo cp deployments/systemd/cf-sync.service /etc/systemd/system/cf-sync.service
   sudo systemctl daemon-reload
   ```

5. **Restart the service** and verify:
   ```bash
   sudo systemctl restart cf-sync
   journalctl -u cf-sync -n 50 --no-pager
   ```

6. **After confirming the new layout works**, remove the old root:
   ```bash
   sudo mv /etc/security-automation /etc/security-automation.v12.bak
   ```

---

## No Backward Compatibility

There is no dual-path support, no automatic detection of `/etc/security-automation/`, and no warning/fallback. If the new layout is absent, the binary will fail at startup with an explicit error from the first config read that requires a missing path. This is intentional: fail clearly rather than silently using wrong secrets.

---

## Auth Recommendation (non-breaking, documentation only)

The bootstrap admin credential (initial setup password at `runtime/initial-admin-password`) is a transient file written on first start and truncated after the operator sets a permanent password. Permanent admin credentials are stored in SQLite (`ui_settings` table) as a bcrypt hash.

No auth migration is required for v1.4. The file paths for both credentials change only in directory prefix (from `/etc/security-automation/` to `/etc/security-automation-go/`).
