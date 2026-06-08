# AI Provider Activation

This document describes how to activate the already-implemented AI providers
for AI Explain and the local provider management UI.

## Activation model

The runtime is fail-closed:

- provider disabled by default
- missing model disables the provider
- missing credential in SQLite disables the provider
- the old `/etc/security-automation-go/secrets/` layout is import-only

## Operator workflow

1. Start the service with the normal bootstrap env file:

   ```bash
   sudo install -d -m 755 -o root -g root /etc/security-automation-go
   sudo install -m 644 -o root -g root /dev/null /etc/security-automation-go/security-automation.env
   ```

2. Open the local operator UI and go to `/providers`.

3. Set the provider model and save the credential in SQLite through the UI.

4. If you are migrating an old machine, use `Import Legacy` once to move files
   from `/etc/security-automation-go/secrets/` into SQLite.

5. Restart the `cmd/cf-sync -mode ui` process if required by your deployment.

## UI management

Open `/providers` in the local operator UI:

- `Replace Key` updates the encrypted SQLite credential
- `Test Provider` performs a short provider check and stores only redacted
  status metadata
- `Enable Provider` and `Disable Provider` toggle the non-secret state only

The UI never pre-fills a secret and never returns the raw key in HTML or JSON.

## Validation

- OpenAI: READY once `AI_EXPLAIN_ENABLED=true`, the OpenAI provider is enabled
  in the provider state file, the model is set, and the credential exists in
  SQLite.
- Anthropic: READY once `AI_EXPLAIN_ENABLED=true`, the Anthropic provider is
  enabled in the provider state file, the model is set, and the credential
  exists in SQLite.
- Gemini: READY once `AI_EXPLAIN_ENABLED=true`, the Gemini provider is enabled
  in the provider state file, the model is set, and the credential exists in
  SQLite.

## Security constraints

- auth required
- CSRF required on POST
- secret never logged
- secret never stored in plaintext
- secret never returned in API JSON
- MCP remains read-only
