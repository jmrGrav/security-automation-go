# AI Provider Configuration

This repository activates AI providers through file-backed secrets plus a
non-secret provider state file. It does not consume raw provider tokens from the
environment.

## Paths

Secrets:

- `/etc/security-automation-go/secrets/openai_api_key`
- `/etc/security-automation-go/secrets/anthropic_api_key`
- `/etc/security-automation-go/secrets/gemini_api_key`

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
- `AI_PROVIDER_OPENAI_API_KEY_FILE`

Anthropic:

- `AI_PROVIDER_ANTHROPIC_ENABLED`
- `AI_PROVIDER_ANTHROPIC_MODEL`
- `AI_PROVIDER_ANTHROPIC_API_KEY_FILE`

Gemini:

- `AI_PROVIDER_GEMINI_ENABLED`
- `AI_PROVIDER_GEMINI_MODEL`
- `AI_PROVIDER_GEMINI_API_KEY_FILE`

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
sudo install -d -m 755 -o root -g root /etc/security-automation
sudo install -d -m 755 -o root -g root /etc/security-automation-go/providers
sudo install -d -m 700 -o root -g root /etc/security-automation-go/secrets
sudo install -m 640 -o root -g security-automation /dev/null /etc/security-automation-go/providers/ai-providers.env
sudo install -m 600 -o root -g root /dev/null /etc/security-automation-go/secrets/openai_api_key
sudo install -m 600 -o root -g root /dev/null /etc/security-automation-go/secrets/anthropic_api_key
sudo install -m 600 -o root -g root /dev/null /etc/security-automation-go/secrets/gemini_api_key
```

If the process cannot write to the state or secret paths, do not bypass the
boundary. The UI must display the failed path and the corresponding `sudo`
command.

If the `security-automation` group does not exist on the host, keep the state
file `root:root` and let the runtime read it at startup with elevated
privileges.

## Behavior

- Providers are disabled by default.
- `Replace Key` writes only the chosen secret file.
- `Enable` refuses to activate a provider if the secret file is missing or
  unreadable.
- `Test Provider` records only redacted test metadata.
- Secrets are never returned in HTML, JSON, logs, audit payloads, or SQLite.

## Validation

1. Set the explicit `AI_EXPLAIN_*` and `AI_PROVIDER_*` environment variables.
2. Create the secret files under `/etc/security-automation-go/secrets`.
3. Start the UI runtime (`cmd/cf-sync -mode ui`).
4. Open `/providers` and verify the management cards show status and redacted
   paths only.
5. Use `Test Provider` to confirm the provider responds without exposing the
   key.
