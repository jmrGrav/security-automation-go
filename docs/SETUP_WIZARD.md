# Setup Wizard Reference

The setup wizard runs automatically on the first browser access after installation.
All normal routes are blocked until setup is complete.

## Steps

| Step | Title | Required? | What it does |
|------|-------|-----------|-------------|
| 1 | Login | Yes | Accepts the one-time setup password from `/etc/security-automation/runtime/initial-admin-password` |
| 2 | Set admin password | Yes | Replaces the one-time password with a bcrypt-hashed permanent password. Invalidates the initial-password file. |
| 3 | UI bind/port | No | Confirms or changes the UI listen address. Port changes require a service restart. |
| 4 | Cloudflare token | No | Validates and stores the CF API token. Required for CF mutations. |
| 5 | AbuseIPDB key | No | Validates and stores the AbuseIPDB API key for IP reputation reporting. |
| 6 | BetterStack token | No | Validates and stores the BetterStack source token for log forwarding. |
| 7 | AI provider keys | No | Stores OpenAI / Anthropic / Gemini API keys for AI-powered explanations. |
| 8 | Runtime summary | No | Read-only view of current configuration before going live. |
| 9 | Production mode | No | Explicitly enables `dry_run=false` and `mutations_enabled=true`. Requires checkbox confirmation. |

## After Setup

- Normal UI routes become accessible
- The wizard is inaccessible (redirects to dashboard)
- To re-enter setup: stop the service, delete the setup state, restart

## Dry-Run Default

The service always starts in dry-run mode. Step 9 is the ONLY place that enables production mutations, and only after explicit confirmation. If you skip step 9, mutations remain disabled — you can enable them later via Settings.

## Wizard State

Progress is stored in the `setup_state` SQLite table. If the service restarts mid-wizard, the browser will be redirected to the last completed step.
