# Security Model

## Credential Handling

- All secret values are stored on disk at mode 0600
- Secret values are never written to logs, audit trails, HTTP responses, or error messages
- The setup wizard displays a token/key field as `type="password"` and never echoes the value after save
- Bcrypt cost 12 is used for all password hashes — no plaintext passwords are retained after hashing
- The initial setup password is stored in plaintext once (for the operator to read) and truncated immediately after the operator sets a permanent password

## Setup Guard

- When `setup_complete=false` in SQLite, all routes except `/setup/*`, `/login`, and `/logout` return HTTP 302 to the current wizard step
- Mutations (`mutations_enabled=true`) are impossible until setup is complete — the config layer enforces this at startup and the wizard enforces it at the confirmation step
- `dry_run=true` is the compiled default and must be explicitly overridden — it cannot be enabled "by accident"

## Authentication

- Session cookies are `HttpOnly`, `SameSite=Lax`
- Session tokens are 32 bytes of `crypto/rand`
- Session TTL is 8 hours
- Rate limiting is applied to login attempts per client IP
- CSRF tokens are HMAC-SHA256 over the session token — all mutation POST handlers call `validCSRF(r)` before processing

## Token Storage

- Operator-configured credentials live in SQLite `credential_secrets`
- Values are encrypted at rest with `/var/lib/security-automation-go/secret.key`
- The setup wizard validates a token before saving it
- Legacy files under `/etc/security-automation-go/secrets/` are import-only and are not used at runtime

## Minimal Footprint

- The wizard only stores secrets the operator explicitly provides — optional steps (AbuseIPDB, BetterStack, AI) write nothing if skipped
- `/var/lib/security-automation-go/runtime/initial-admin-password` is invalidated after step 2 so the bootstrap password cannot be reused
