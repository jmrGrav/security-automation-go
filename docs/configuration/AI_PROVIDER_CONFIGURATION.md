# AI Provider Configuration

This repository activates AI providers through encrypted SQLite credentials
plus a non-secret provider state file. It does not consume raw provider tokens
from the environment.

## Paths

Credentials:

- SQLite `credential_secrets` table

State:

- `/etc/security-automation-go/providers/ai-providers.env`

Environment source:

- the UI runtime uses the normal process environment
- example file: [`configs/ai-providers.example.env`](../configs/ai-providers.example.env)

## Runtime environment variables

Core gateway:

- `AI_EXPLAIN_ENABLED`
- `AI_EXPLAIN_PROVIDER_STRATEGY`
- `AI_EXPLAIN_MAX_CONTEXT_BYTES`
- `AI_EXPLAIN_MAX_OUTPUT_TOKENS`
- `AI_EXPLAIN_TIMEOUT`
- `AI_EXPLAIN_RATE_LIMIT_PER_MINUTE`
- `AI_EXPLAIN_CACHE_TTL`
- `AI_EXPLAIN_STRICT_NO_TOOLS`

OpenAI:

- `AI_PROVIDER_OPENAI_ENABLED`
- `AI_PROVIDER_OPENAI_MODEL`

Anthropic:

- `AI_PROVIDER_ANTHROPIC_ENABLED`
- `AI_PROVIDER_ANTHROPIC_MODEL`

Gemini:

- `AI_PROVIDER_GEMINI_ENABLED`
- `AI_PROVIDER_GEMINI_MODEL`

## Provider state file

The non-secret provider state file uses canonical provider names and is written
by the local UI:

- `OPENAI_ENABLED`
- `OPENAI_MODEL`
- `OPENAI_LAST_TEST_AT`
- `OPENAI_LAST_TEST_STATUS`
- `OPENAI_LAST_TEST_LATENCY_MS`
- `OPENAI_LAST_ERROR_CODE`
- `ANTHROPIC_ENABLED`
- `ANTHROPIC_MODEL`
- `ANTHROPIC_LAST_TEST_AT`
- `ANTHROPIC_LAST_TEST_STATUS`
- `ANTHROPIC_LAST_TEST_LATENCY_MS`
- `ANTHROPIC_LAST_ERROR_CODE`
- `GEMINI_ENABLED`
- `GEMINI_MODEL`
- `GEMINI_LAST_TEST_AT`
- `GEMINI_LAST_TEST_STATUS`
- `GEMINI_LAST_TEST_LATENCY_MS`
- `GEMINI_LAST_ERROR_CODE`

## Permissions

Recommended operator setup:

```bash
sudo install -d -m 755 -o root -g root /etc/security-automation-go
sudo install -m 0644 -o root -g root /dev/null /etc/security-automation-go/security-automation.env
```

If the process cannot write to the state or master-key paths, do not bypass the
boundary. The UI must display the failed path and the corresponding `sudo`
command.

The `security-automation` group owns the state directory and encrypted
credential store. The master key lives in `/var/lib/security-automation-go/`.

## Behavior

- Providers are disabled by default.
- `Replace Key` writes only the chosen encrypted SQLite credential row.
- `Enable` refuses to activate a provider if the credential is missing.
- `Test Provider` records only redacted test metadata.
- Tokens are never returned in HTML, JSON, logs, audit payloads, support
  bundles, or plaintext SQLite.

## Validation

1. Set the explicit `AI_EXPLAIN_*` and `AI_PROVIDER_*` environment variables.
2. Start the UI runtime (`cmd/cf-sync -mode ui`).
3. Open `/providers` and verify the management cards show SQLite-backed status.
4. Use `Test Provider` to confirm the provider responds without exposing the
   key.
