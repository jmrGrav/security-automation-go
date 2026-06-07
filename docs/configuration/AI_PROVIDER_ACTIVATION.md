# AI Provider Activation

This document describes how to activate the already-implemented AI providers
for AI Explain and the local provider management UI.

## Activation model

The runtime is fail-closed:

- provider disabled by default
- missing model disables the provider
- missing or unreadable secret file disables the provider
- no raw `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GEMINI_API_KEY` values are
  consumed

## Operator workflow

1. Create the non-secret state file:

   ```bash
   sudo install -d -m 755 -o root -g root /etc/security-automation-go
   sudo install -d -m 755 -o root -g root /etc/security-automation-go/providers
   sudo install -m 640 -o root -g security-automation /dev/null /etc/security-automation-go/providers/ai-providers.env
   ```

2. Create the provider secret files:

   ```bash
   sudo install -d -m 700 -o root -g root /etc/security-automation-go/secrets
   sudo install -m 600 -o root -g root /dev/null /etc/security-automation-go/secrets/openai_api_key
   sudo install -m 600 -o root -g root /dev/null /etc/security-automation-go/secrets/anthropic_api_key
   sudo install -m 600 -o root -g root /dev/null /etc/security-automation-go/secrets/gemini_api_key
   ```

3. Write the key into the matching file with an editor such as `sudoedit`.

4. Set the explicit provider flags in the UI runtime environment:

   - `AI_EXPLAIN_ENABLED=true`
   - `AI_PROVIDER_OPENAI_ENABLED=true|false`
   - `AI_PROVIDER_OPENAI_MODEL=...`
   - `AI_PROVIDER_OPENAI_API_KEY_FILE=/etc/security-automation-go/secrets/openai_api_key`
   - `AI_PROVIDER_ANTHROPIC_ENABLED=true|false`
   - `AI_PROVIDER_ANTHROPIC_MODEL=...`
   - `AI_PROVIDER_ANTHROPIC_API_KEY_FILE=/etc/security-automation-go/secrets/anthropic_api_key`
   - `AI_PROVIDER_GEMINI_ENABLED=true|false`
   - `AI_PROVIDER_GEMINI_MODEL=...`
   - `AI_PROVIDER_GEMINI_API_KEY_FILE=/etc/security-automation-go/secrets/gemini_api_key`

5. Restart the `cmd/cf-sync -mode ui` process.

## UI management

Open `/providers` in the local operator UI:

- `Replace Key` updates the matching secret file atomically.
- `Test Provider` performs a short provider check and stores only redacted
  status metadata.
- `Enable Provider` and `Disable Provider` toggle the non-secret state only.

The UI never pre-fills a secret and never returns the raw key in HTML or JSON.

## Validation

- OpenAI: READY once `AI_EXPLAIN_ENABLED=true`, the OpenAI provider is enabled
  in `/etc/security-automation-go/providers/ai-providers.env`, the model is set,
  and the secret file is readable.
- Anthropic: READY once `AI_EXPLAIN_ENABLED=true`, the Anthropic provider is
  enabled in `/etc/security-automation-go/providers/ai-providers.env`, the model is
  set, and the secret file is readable.
- Gemini: READY once `AI_EXPLAIN_ENABLED=true`, the Gemini provider is enabled
  in `/etc/security-automation-go/providers/ai-providers.env`, the model is set,
  and the secret file is readable.

## Security constraints

- auth required
- CSRF required on POST
- secret never logged
- secret never stored in SQLite
- secret never returned in API JSON
- MCP remains read-only
