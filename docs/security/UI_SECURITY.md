# UI Security

## Scope

The local operator UI is a browser-facing control surface for inspection and
explicitly approved actions. It is not a public API.

## Default posture

- `UI_ENABLED=0`
- bind to `127.0.0.1:9090` when enabled
- read-only by default
- no destructive UI actions unless `UI_MUTATIONS_ENABLED=1`
- no live Cloudflare mutation unless `CLOUDFLARE_MUTATIONS_ENABLED=1`
- the shell is self-contained and uses `script-src 'self'`

## Authentication

- Authentication is local and mandatory.
- Session cookies are `HttpOnly` and `SameSite=Lax`.
- `Secure` is set when the request is already HTTPS.
- The UI secret lives in `UI_SECRET` and/or `UI_SECRET_FILE`.

## CSRF

- Every mutation route requires a CSRF token.
- The token is derived from the local session and UI secret.
- Missing or invalid CSRF fails closed.

## Secrets

- Provider API keys must never be logged or rendered in full.
- Provider keys are stored in the encrypted SQLite credential store.
- Legacy `/etc/security-automation-go/secrets/` files are import-only and are not a runtime source.
- If a secret has been pasted into a prompt or temporary note, rotate it.

## Operator expectations

- Dashboard status must clearly distinguish:
  - `CrowdSec unavailable / read-only fallback`
  - `OpenResty unavailable / nginx log mode`
  - `Cloudflare configured dry-run`
  - `Cloudflare live mutations enabled`
- UI action audit entries must not contain raw secrets.
- reserved future routes must still require auth even when they render a
  coming-soon state.
- active read-only operator routes such as `/intelligence` and
  `/trusted-networks` must also stay self-contained, secret-safe, and
  mutation-free.
