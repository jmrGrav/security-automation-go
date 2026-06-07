# Secret Loading Model

**Updated:** 2026-06-07
**Canonical install root:** `/etc/security-automation-go/`

---

## Overview

cf-sync manages two categories of secrets:
1. **Written by the wizard** — operator-provided credentials entered during the setup wizard
2. **Runtime-generated** — passwords and tokens created by the service itself

All secret files must be mode **0600**, owned by root. The setup wizard enforces this via `WriteSecretFile` (tmp file → rename → chmod 0600, atomic). This pattern is correct for all wizard-written secrets.

---

## Canonical Secret Registry

| Secret | Canonical File | Format | Written By | Loaded By | Mode |
|--------|---------------|--------|-----------|-----------|------|
| CF API Token | `/etc/security-automation-go/secrets/cloudflare_api_token` | `CF_API_TOKEN=<value>` | Wizard step 4 (`cfTokenSecretPath`) | EnvironmentFile in systemd unit | daemon |
| AbuseIPDB Key | `/etc/security-automation-go/secrets/abuseipdb_api_key` | `ABUSEIPDB_KEY=<value>` | Wizard step 5 | EnvironmentFile → `ABUSEIPDB_KEY` env var | daemon |
| BetterStack Token | `/etc/security-automation-go/secrets/betterstack_source_token` | `BETTERSTACK_SOURCE_TOKEN=<value>` | Wizard step 6 | EnvironmentFile → `BETTERSTACK_SOURCE_TOKEN` env var | daemon |
| OpenAI Key | `/etc/security-automation-go/secrets/openai_api_key` | raw value | Wizard step 7 (`openAISecretPath`) | `AI_PROVIDER_OPENAI_API_KEY_FILE` → file path read by ai.Config | daemon |
| Anthropic Key | `/etc/security-automation-go/secrets/anthropic_api_key` | raw value | Wizard step 7 (`anthropicSecretPath`) | `AI_PROVIDER_ANTHROPIC_API_KEY_FILE` → file path | daemon |
| Gemini Key | `/etc/security-automation-go/secrets/gemini_api_key` | raw value | Wizard step 7 (`geminiSecretPath`) | `AI_PROVIDER_GEMINI_API_KEY_FILE` → file path | daemon |
| Admin Password | `/etc/security-automation-go/secrets/admin_password` | JSON bcrypt hash | Wizard step 2 | `cfg.UI.AdminPasswordFile` (default path matches) | ui |
| Initial Password | `/etc/security-automation-go/runtime/initial-admin-password` | plaintext (one-time) | Runtime (service startup) | Read by operator; truncated after step 2 | ui |

**Legend:**
- **daemon** = loaded at daemon startup via EnvironmentFile or config
- **ui** = loaded by the UI server at startup

---

## Legacy Path Warning

The directory `/etc/security-automation/` (without `-go`) is the **pre-V1.4 config root**.
It was removed from all code in V1.4. No daemon, wizard, or systemd unit reads from it.

If this directory exists on disk alongside `/etc/security-automation-go/`, the health check
`layout` will return YELLOW. If it is the only config root (canonical absent), the health
check returns RED and secrets will not load.

**Operator migration command** (one-time, after V1.4 upgrade):
```bash
sudo mkdir -p /etc/security-automation-go/secrets
sudo chmod 700 /etc/security-automation-go/secrets
sudo cp /etc/security-automation/secrets/cloudflare_api_token /etc/security-automation-go/secrets/
sudo cp /etc/security-automation/secrets/abuseipdb_api_key    /etc/security-automation-go/secrets/
sudo cp /etc/security-automation/secrets/anthropic_api_key    /etc/security-automation-go/secrets/
sudo cp /etc/security-automation/secrets/openai_api_key       /etc/security-automation-go/secrets/
sudo cp /etc/security-automation/secrets/gemini_api_key       /etc/security-automation-go/secrets/
sudo chmod 0600 /etc/security-automation-go/secrets/*
# Verify the service loads them, then archive the old directory:
sudo mv /etc/security-automation /etc/security-automation.v13.bak
```

---

## CF API Token — Loading Chain

The Cloudflare API token uses EnvironmentFile loading:

| Side | Path |
|------|------|
| Wizard writes to (`cfTokenSecretPath` const) | `/etc/security-automation-go/secrets/cloudflare_api_token` |
| Systemd EnvironmentFile loads from | `/etc/security-automation-go/secrets/cloudflare_api_token` |

Both sides are in sync. The file is in env-file format: `CF_API_TOKEN=<value>`.

The EnvironmentFile directive uses the `-` optional prefix:
```ini
EnvironmentFile=-/etc/security-automation-go/secrets/cloudflare_api_token
```
This means the service starts cleanly when the token has not yet been configured.

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

---

## Secret Validation Before Write

The wizard validates secrets against external APIs before writing them to disk:

- **CF API Token (step 4):** Validated against the Cloudflare API. An invalid token is rejected before reaching `WriteSecretFile`.
- **AbuseIPDB Key (step 5):** Validated against the AbuseIPDB check endpoint.
- **BetterStack Token (step 6):** Validated against the BetterStack ingest endpoint.
- **AI keys (step 7):** Validated via a test request to each provider.

If validation fails, no file is written. This prevents storing non-functional credentials.

---

## Env-File Format Reference

All secret files written by the wizard use standard env-file format:

```
KEY=VALUE
```

One key-value pair per file. No quotes required (systemd's `EnvironmentFile` parser handles unquoted values). No shell escaping. The value is everything after the first `=` on the line.

Example — `/etc/security-automation-go/secrets/cloudflare_api_token`:
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
sudo find /etc/security-automation-go/secrets/ -type f -exec ls -la {} \;
```

All files should show:
```
-rw------- 1 root root  ...  /etc/security-automation-go/secrets/<name>
```

If any file shows group or world read bits, fix immediately:

```bash
sudo chmod 0600 /etc/security-automation-go/secrets/*
```
