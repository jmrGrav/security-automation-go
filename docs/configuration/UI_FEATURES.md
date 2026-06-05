# UI Features

## Current shell

The local operator UI now uses a shared self-contained shell with a persistent
sidebar and active navigation state. The shell is local-only and does not rely
on a third-party script origin.

## Implemented routes

- `/` Dashboard++
- `/providers` Provider Management
- `/forensic` Forensic lookup
- `/audit` Audit Trail foundation
- `/about` and `/system` About/System foundation
- `/intelligence` Security Intelligence read-only lookup
- `/trusted-networks` Trusted Networks Explorer read-only registry view

## Reserved routes

These routes are protected and intentionally render a coming-soon state:

- `/timeline`
- `/cloudflare/diff`
- `/replay`
- `/deban`
- `/recovery`
- `/drift`

Future operator pages will continue to expand the same shared shell without
introducing live mutation writers in the UI.

## Security posture

- Auth is required on every route except `/login`.
- `Cache-Control: no-store` applies to authenticated pages.
- Mutations remain disabled by default.
- Cloudflare live mutations remain disabled by default.
- CSRF is required for mutation routes.
- Provider keys are masked and never rendered in full, and provider state is
  stored separately from raw secrets in `/etc/security-automation/providers/ai-providers.env`.
