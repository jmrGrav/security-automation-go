# AI Provider Operator Guide

This repository stores operator-configured provider credentials in encrypted
SQLite, not in `/etc/security-automation-go/secrets/`.

The runtime source of truth is `credential_secrets` in
`/var/lib/security-automation-go/runtime.db`.

## Credential storage

- Cloudflare API token
- Cloudflare Zone ID
- AbuseIPDB key
- BetterStack token
- OpenAI key
- Anthropic key
- Gemini key
- future provider tokens added through the UI

These values are written by the first-run wizard or by `/providers` in the UI.
They are encrypted at rest with the local master key at
`/var/lib/security-automation-go/secret.key`.

## Bootstrap files

The only `/etc/security-automation-go/` file required for normal startup is the
non-secret bootstrap env file:

- `/etc/security-automation-go/security-automation.env`

That file is limited to address, port, state directory, and other non-secret
bootstrap values.

## Legacy import

If an old installation still has files under `/etc/security-automation-go/secrets/`,
they can be imported once through the UI:

- `POST /admin/providers/import-legacy`

The import is explicit, idempotent, and legacy-only. The runtime does not read
those files during normal operation.

## Provider state

Non-secret provider state still lives in:

- `/var/lib/security-automation-go/runtime/ai-providers.env`

It stores enable flags, model names, and test metadata only.

## UI workflow

Open `/providers` in the local operator UI to:

- replace a credential
- test a provider
- enable or disable a provider
- import legacy files explicitly

The UI never echoes a stored credential after save.

## Security rules

- Never log provider key contents.
- Never expose decrypted credentials in diagnostics, support bundles, or audit.
- Never treat `/etc/security-automation-go/secrets/` as a runtime source.
