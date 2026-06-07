# Secret Loading Model

**Date:** 2026-06-06
**Sprint:** V1.2 Configuration Consolidation
**Purpose:** Document the canonical source, format, and loading mechanism for every secret the cf-sync system manages. Identify the one known mismatch and the orphaned legacy files.

---

## Overview

cf-sync manages two categories of secrets:
1. **Written by the wizard** — operator-provided credentials entered during the setup wizard
2. **Runtime-generated** — passwords and tokens created by the service itself

All secret files must be mode **0600**, owned by the service user (or root). The setup wizard enforces this via `WriteSecretFile` (tmp file → rename → chmod 0600, atomic). This pattern is correct for all wizard-written secrets.

---

## Canonical Secret Registry

| Secret | Canonical File | Format | Written By | Loaded By | Mode |
|--------|---------------|--------|-----------|-----------|------|
| CF API Token | `/etc/security-automation/secrets/cloudflare_api_token` | `CF_API_TOKEN=<value>` | Wizard step 4 (`cfTokenSecretPath`) | EnvironmentFile in systemd unit | daemon |
| AbuseIPDB Key | `/etc/security-automation/secrets/abuseipdb_api_key` | `ABUSEIPDB_KEY=<value>` | Wizard step 5 | EnvironmentFile → `ABUSEIPDB_KEY` env var | daemon |
| BetterStack Token | `/etc/security-automation/secrets/betterstack_source_token` | `BETTERSTACK_SOURCE_TOKEN=<value>` | Wizard step 6 | EnvironmentFile → `BETTERSTACK_SOURCE_TOKEN` env var | daemon |
| OpenAI Key | `/etc/security-automation/secrets/openai_api_key` | `OPENAI_API_KEY=<value>` | Wizard step 7 (`openAISecretPath`) | `AI_PROVIDER_OPENAI_API_KEY_FILE` → file path read by ai.Config | daemon |
| Anthropic Key | `/etc/security-automation/secrets/anthropic_api_key` | `ANTHROPIC_API_KEY=<value>` | Wizard step 7 (`anthropicSecretPath`) | `AI_PROVIDER_ANTHROPIC_API_KEY_FILE` → file path | daemon |
| Gemini Key | `/etc/security-automation/secrets/gemini_api_key` | `GEMINI_API_KEY=<value>` | Wizard step 7 (`geminiSecretPath`) | `AI_PROVIDER_GEMINI_API_KEY_FILE` → file path | daemon |
| Admin Password | `/etc/security-automation/secrets/admin_password` | JSON bcrypt hash | Wizard step 2 | `cfg.UI.AdminPasswordFile` (default path matches) | ui |
| Initial Password | `/etc/security-automation/runtime/initial-admin-password` | plaintext (one-time) | Runtime (service startup) | Read by operator; truncated after step 2 | ui |

**Legend:**
- **daemon** = loaded at daemon startup via EnvironmentFile or config
- **ui** = loaded by the UI server at startup

---

## The One Known Mismatch (Critical — F1)

### CF API Token Filename Mismatch

**Current state (broken):**

| Side | Path |
|------|------|
| Wizard writes to (`cfTokenSecretPath` const) | `/etc/security-automation/secrets/cloudflare_api_token` |
| Systemd EnvironmentFile loads from | `/etc/security-automation/secrets/cf_sync_api_token.env` |

These are different filenames. The daemon never loads the file the wizard writes.

**Root cause:**
The constant `cfTokenSecretPath` in `internal/ui/setup_wizard.go` and the `EnvironmentFile=` line in the systemd unit were not kept in sync. The systemd unit uses a name from an earlier naming scheme (`cf_sync_api_token.env`); the docs and `INSTALL_LAYOUT.md` use `cloudflare_api_token`.

**The correct canonical path** (per `docs/INSTALL_LAYOUT.md` and `docs/SECURITY_MODEL.md`) is:
```
/etc/security-automation/secrets/cloudflare_api_token
```

**Required fix:**
Update the `EnvironmentFile=` line in the systemd unit (both `deployments/systemd/cf-sync.service` and `/etc/systemd/system/cf-sync.service`):

```ini
# BEFORE (wrong):
EnvironmentFile=/etc/security-automation/secrets/cf_sync_api_token.env

# AFTER (correct):
EnvironmentFile=-/etc/security-automation/secrets/cloudflare_api_token
```

Note the `-` prefix: this makes the EnvironmentFile optional. If the operator has not yet run wizard step 4, the service starts without the token (correct — in dry-run mode it does not need it).

**Do NOT rename the file the wizard writes.** The wizard path matches the docs. Fix the systemd reference.

**Apply with:**
```bash
sudo systemctl daemon-reload
sudo systemctl restart cf-sync
```

---

## Atomic Write Protocol (Already Correct)

All wizard-written secrets use the `WriteSecretFile` function, which:
1. Creates a temporary file in the same directory (same filesystem → rename is atomic)
2. Writes the value in env-file format (`KEY=VALUE`)
3. `fsync`s the file
4. Closes the file
5. `os.Rename` (atomic on POSIX) to the final path
6. `chmod 0600` on the final path

This pattern is correct and consistent. No secret is ever partially written from the reader's perspective. All secrets are mode 0600 — never world-readable.

**Do not change this pattern.** It satisfies the security model in `docs/SECURITY_MODEL.md`.

---

## Secret Validation Before Write

The wizard validates secrets against external APIs before writing them to disk. Specifically:

- **CF API Token (step 4):** Validated against the Cloudflare API. An invalid token is rejected before reaching `WriteSecretFile`.
- **AbuseIPDB Key (step 5):** Validated against the AbuseIPDB check endpoint.
- **BetterStack Token (step 6):** Validated against the BetterStack ingest endpoint.
- **AI keys (step 7):** Validated via a test request to each provider.

If validation fails, no file is written. This prevents storing non-functional credentials.

---

## Orphaned Legacy Secrets

These files exist on disk but are not part of the canonical loading model. They must be cleaned up.

### `/etc/security-automation-go/cf-shadow.env`

- **What it is:** The EnvironmentFile loaded by the legacy systemd unit (REQUIRED, no `-` prefix)
- **What it contains:** Environment variable overrides for the legacy `cf-shadow` config, likely including a CF API token under a non-standard variable name
- **Risk:** The live daemon currently loads this file. It may contain credentials that differ from what the wizard has stored. After migration, this file is no longer referenced by systemd and becomes an orphan.
- **Action:** Archive alongside `cf-shadow.yaml` in `/etc/security-automation-go.bak/`. Delete 30 days after migration confirms stable.

### `/etc/crowdsec/cf-sync.env`

- **What it is:** Legacy env file from the Python cf-sync predecessor daemon
- **What it contains:** A Cloudflare API token that has since been revoked
- **Risk:** No active service loads this file (confirmed: not referenced by any Go daemon unit). However, it represents a credential hygiene issue — a revoked token left on disk in plaintext.
- **Action:** Delete immediately. The token is revoked, so there is no recovery concern.

```bash
# Confirm nothing reads this file
sudo grep -r 'crowdsec/cf-sync.env' /etc/systemd/ /etc/cron* 2>/dev/null || echo "Not referenced — safe to delete"
sudo rm /etc/crowdsec/cf-sync.env
```

---

## Env-File Format Reference

All secret files written by the wizard use standard env-file format:

```
KEY=VALUE
```

One key-value pair per file. No quotes required (systemd's `EnvironmentFile` parser handles unquoted values). No shell escaping. The value is everything after the first `=` on the line.

Example — `/etc/security-automation/secrets/cloudflare_api_token`:
```
CF_API_TOKEN=v1.0-xxxxxxxxxxxxxxxxxxxxxxxx-yyyyyyyyyyyyyyyy
```

This format is compatible with:
- systemd `EnvironmentFile=` directive (native support)
- `source /path/to/file && echo $CF_API_TOKEN` (manual operator verification)
- `export $(grep -v '^#' /path/to/file | xargs)` (shell loading for debugging)

---

## Secret Permissions Verification

To audit all secret files at once:

```bash
sudo find /etc/security-automation/secrets/ -type f -exec ls -la {} \;
```

All files should show:
```
-rw------- 1 root root  ...  /etc/security-automation/secrets/<name>
```

If any file shows group or world read bits (`-rw-r--r--` or `-rw-rw----`), fix immediately:

```bash
sudo chmod 0600 /etc/security-automation/secrets/*
```
