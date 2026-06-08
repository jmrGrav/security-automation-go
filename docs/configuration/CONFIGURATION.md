# Configuration

## Bootstrap file

The only file required for normal startup is the non-secret bootstrap env:

```
/etc/security-automation-go/security-automation.env
```

Contains: bind address, port, state directory, and other non-secret bootstrap values. No credentials here.

## Authentication

The UI uses password-based authentication with a bcrypt-hashed permanent password stored in SQLite.

- On first boot, a one-time setup secret is written to `/var/lib/security-automation-go/runtime/ui_secret` (mode `0600`)
- After setup completes, sessions use HTTP-only cookies with CSRF protection
- Password minimum: 16 characters with uppercase, lowercase, digits, and symbols
- Rate limiting is enforced on login attempts

See [FIRST_BOOT.md](../installation/FIRST_BOOT.md) for the initial setup procedure.

## Secrets layout

Credentials are stored in encrypted SQLite (`credential_secrets` table at `/var/lib/security-automation-go/runtime.db`).

Non-secret state: `/etc/security-automation-go/` and `/var/lib/security-automation-go/runtime/`.

The legacy `/etc/security-automation-go/secrets/` layout is import-only — the runtime does not read it during normal operation.

## AI providers

See [AI_PROVIDERS.md](AI_PROVIDERS.md) for provider-specific configuration.

## UI configuration

See [UI_CONFIGURATION.md](UI_CONFIGURATION.md) for UI routing and appearance options.
