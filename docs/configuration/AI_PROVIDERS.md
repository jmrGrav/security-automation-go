# AI Providers

Credentials are stored in encrypted SQLite (`credential_secrets` table), not in flat files under `/etc/security-automation-go/secrets/`.

Runtime source of truth: `/var/lib/security-automation-go/runtime.db`.

## Activation model

Providers are disabled by default.

- missing model → provider disabled
- missing credential in SQLite → provider disabled
- the `/etc/security-automation-go/secrets/` layout is import-only (see Legacy import below)

## Environment variables

Core gateway:

- `AI_EXPLAIN_ENABLED`
- `AI_EXPLAIN_PROVIDER_STRATEGY`
- `AI_EXPLAIN_MAX_CONTEXT_BYTES`
- `AI_EXPLAIN_MAX_OUTPUT_TOKENS`
- `AI_EXPLAIN_TIMEOUT`
- `AI_EXPLAIN_RATE_LIMIT_PER_MINUTE`
- `AI_EXPLAIN_CACHE_TTL`
- `AI_EXPLAIN_STRICT_NO_TOOLS`

Per-provider (replace `OPENAI` with `ANTHROPIC` or `GEMINI` as needed):

- `AI_PROVIDER_OPENAI_ENABLED`
- `AI_PROVIDER_OPENAI_MODEL`

State file: `/var/lib/security-automation-go/runtime/ai-providers.env` — enable flags, model names, and test metadata only.

## UI workflow

Open `/v2/providers` in the local operator UI:

- `Replace Key` updates the encrypted SQLite credential
- `Test Provider` performs a short provider check — records only redacted status metadata
- `Enable Provider` / `Disable Provider` toggle the non-secret state only

The UI never echoes a stored credential after save and never pre-fills a secret in HTML.

## Legacy import

To migrate an old installation that still has files under `/etc/security-automation-go/secrets/`:

1. Open `/v2/providers` in the UI.
2. Click `Import Legacy` once.
3. The runtime does not read legacy files during normal operation.

## Security rules

- Tokens are never returned in HTML, JSON, logs, audit payloads, or plaintext SQLite.
- `Enable` refuses to activate a provider if the credential is missing.
- CSRF required on all POST endpoints.
- MCP remains read-only.
