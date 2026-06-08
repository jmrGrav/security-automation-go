# Secret Loading Model

**Updated:** 2026-06-07

## Current model

The operator-facing credentials are no longer file-backed secrets in `/etc`.
They are stored in SQLite as encrypted rows in `credential_secrets`.

The local machine provides one file-backed secret:

- `/var/lib/security-automation-go/secret.key`

That file is the master key used to encrypt and decrypt operator credentials
at rest. It must remain on disk, mode `0600`, owned by
`security-automation:security-automation`.

Bootstrap-only configuration may still live in:

- `/etc/security-automation-go/security-automation.env`

That file must not contain operator credentials. It is only for address, port,
state directory, and other non-secret bootstrap values.

## Stored credentials

The encrypted SQLite store is the source of truth for:

- Cloudflare API token
- Cloudflare Zone ID
- AbuseIPDB key
- BetterStack token
- OpenAI key
- Anthropic key
- Gemini key
- future provider tokens added through the UI

The UI wizard and provider admin pages write to SQLite only.

## Master key behavior

- New installation: the master key is generated automatically.
- Existing encrypted credentials and missing master key: fail closed with a
  clear operator error.
- The key is never logged, exported in diagnostics, or written to the support
  bundle.

## Legacy import

Legacy files under `/etc/security-automation-go/secrets/` are import-only.
They are not part of runtime lookup.

Import happens only through the explicit UI action:

- `POST /admin/providers/import-legacy`

The import is one-shot and idempotent. After a successful import, runtime uses
SQLite only.

## Operational summary

| Location | Purpose |
|----------|---------|
| `/etc/security-automation-go/security-automation.env` | Bootstrap-only, non-secret |
| `/var/lib/security-automation-go/runtime.db` | Settings + encrypted credentials |
| `/var/lib/security-automation-go/secret.key` | Local master key |
| `/var/lib/security-automation-go/runtime/initial-admin-password` | One-time setup password |
| `/var/lib/security-automation-go/runtime/ui_secret` | UI session secret |
| `/etc/security-automation-go/secrets/` | Legacy import source only |

## Fresh install

Fresh install succeeds with:

- no `/etc/security-automation-go/secrets/` directory,
- no operator token files,
- only the bootstrap env file, SQLite, and the runtime directories.

## Migration

If legacy files still exist, the UI can import them into SQLite once. The
runtime does not continue to consult the legacy directory after import.
