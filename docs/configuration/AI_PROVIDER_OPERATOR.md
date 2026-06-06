# AI Provider Operator Guide

This repository uses file-backed provider secrets for AI Explain and provider
management state for the local UI. The runtime expects provider keys to be
stored in owner-only files and referenced through `AI_PROVIDER_*_API_KEY_FILE`.
The non-secret provider state lives in
`/etc/security-automation-go/providers/ai-providers.env`.

## Secret directory

Create the secret directory once:

```bash
sudo install -d -m 700 -o root -g root /etc/security-automation-go/secrets
```

Create the key files with root-only permissions:

```bash
sudo install -m 600 -o root -g root /dev/null /etc/security-automation-go/secrets/openai_api_key
sudo install -m 600 -o root -g root /dev/null /etc/security-automation-go/secrets/anthropic_api_key
sudo install -m 600 -o root -g root /dev/null /etc/security-automation-go/secrets/gemini_api_key
```

Write each provider key into its file without printing the value to the
terminal. Do not commit these files.

## Provider state file

Create the non-secret state file and keep it root-owned. Use
`root:security-automation` when that group exists; otherwise `root:root` is an
acceptable fallback if the process reads the file at startup with elevated
privileges:

```bash
sudo install -d -m 755 -o root -g root /etc/security-automation
sudo install -d -m 755 -o root -g root /etc/security-automation-go/providers
sudo install -m 640 -o root -g security-automation /dev/null /etc/security-automation-go/providers/ai-providers.env
```

The UI writes only non-secret provider state there:

- `OPENAI_ENABLED=true|false, ANTHROPIC_ENABLED=true|false, GEMINI_ENABLED=true|false`
- `OPENAI_MODEL=..., ANTHROPIC_MODEL=..., GEMINI_MODEL=...`
- `OPENAI_LAST_TEST_AT=..., ANTHROPIC_LAST_TEST_AT=..., GEMINI_LAST_TEST_AT=...`
- `OPENAI_LAST_TEST_STATUS=..., ANTHROPIC_LAST_TEST_STATUS=..., GEMINI_LAST_TEST_STATUS=...`
- `OPENAI_LAST_TEST_LATENCY_MS=..., ANTHROPIC_LAST_TEST_LATENCY_MS=..., GEMINI_LAST_TEST_LATENCY_MS=...`
- `OPENAI_LAST_ERROR_CODE=..., ANTHROPIC_LAST_ERROR_CODE=..., GEMINI_LAST_ERROR_CODE=...`

It never stores a raw key, hash, prefix, prompt, payload, or test response.

## UI provider management

Open the local operator UI and use `/providers`:

- `Replace Key` writes the matching secret file atomically.
- `Test Provider` performs a short provider check and stores only redacted
  status metadata.
- `Enable Provider` and `Disable Provider` only toggle the non-secret state
  file.

The UI never pre-fills an existing key and never returns the raw secret in HTML
or JSON.

## Activation flags

Copy [`configs/ai-providers.example.env`](../../configs/ai-providers.example.env)
into the environment source used by the UI runtime, then set the provider flags
explicitly:

- `AI_EXPLAIN_ENABLED=true` to enable the AI Explain gateway
- `OPENAI_ENABLED=true` to activate OpenAI
- `ANTHROPIC_ENABLED=true` to activate Anthropic
- `GEMINI_ENABLED=true` to activate Gemini

Each provider stays disabled if its `*_ENABLED` flag is false, if the model is
missing, or if the key file is missing or unreadable.

## Restart procedure

Restart the process that launches `cmd/cf-sync -mode ui` after updating the
environment, state file, or key files.

## Validation

Use the UI as usual. If a provider is not configured correctly, the gateway
falls back to `provider disabled / unavailable` without exposing the secret
value.

If the process cannot write to `/etc/security-automation-go/providers/ai-providers.env`
or to one of the secret files, the UI shows an operator error with the
recommended `sudo install ...` command instead of bypassing permissions.

## Security rules

- Never store provider keys in the repository.
- Never use raw `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GEMINI_API_KEY`
  values in the runtime.
- Never log provider key contents.
- Keep the MCP server read-only; provider wiring is only for AI Explain.
