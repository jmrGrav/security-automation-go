# Secret Loading Audit

**Date:** 2026-06-07
**Scope:** Every secret read by the runtime. Complete trace from write site to consumer.
**Method:** Direct code read — no assumptions. Every cell in the table is cited to a source file and line number.

---

## Canonical Paths Confirmed

All active Go code, systemd units, and packaging scripts use `/etc/security-automation-go/` exclusively.
No active code reads from `/etc/security-automation/` (without `-go`).

References to the old path exist only in:
- `internal/health/checks.go:273` — `CheckLegacyLayout` detection target (intentional)
- `internal/startuplog/layout_check.go:9` — `DefaultLegacyRoot` constant (intentional)
- `docs/archive/` — frozen historical records

---

## Secret Registry — Complete Loading Chain

| Secret | Canonical Path | Format on Disk | Written By | Source Line | Loaded By | How Loaded | Consumer |
|--------|---------------|----------------|-----------|-------------|-----------|------------|---------|
| **Cloudflare API Token** | `/etc/security-automation-go/secrets/cloudflare_api_token` | `CF_API_TOKEN=<value>` | Wizard step 4 | `setup_wizard.go:297,436` | `cf-sync.service` | `EnvironmentFile=` (mandatory) | `cfg.Cloudflare.APIToken` via `applyEnvOverrides:256` |
| **AbuseIPDB Key** | `/etc/security-automation-go/secrets/abuseipdb_api_key` | `ABUSEIPDB_KEY=<value>` | Wizard step 5 | `setup_wizard.go:300,499` | `security-automation.env` (operator) | `EnvironmentFile=-` (optional env file) | `cfg.AbuseIPDB.APIKey` via `applyEnvOverrides:279` |
| **BetterStack Token** | `/etc/security-automation-go/secrets/betterstack_source_token` | `BETTERSTACK_SOURCE_TOKEN=<value>` | Wizard step 6 | `setup_wizard.go:301,552` | `security-automation.env` (operator) | `EnvironmentFile=-` (optional env file) | `cfg.BetterStack.SourceToken` via `applyEnvOverrides:368` |
| **OpenAI Key** | `/etc/security-automation-go/secrets/openai_api_key` | raw key (provider UI) / `OPENAI_API_KEY=<val>` (wizard) | Provider admin UI | `provider_admin.go:75`, `provider_admin_handlers.go:291,112` | AI gateway at runtime | `ReadAPIKeyFile(path)` | `ai.ProviderConfig.APIKeyFile` → `providers/openai.go:128` |
| **Anthropic Key** | `/etc/security-automation-go/secrets/anthropic_api_key` | raw key (provider UI) / `ANTHROPIC_API_KEY=<val>` (wizard) | Provider admin UI | `provider_admin.go:77`, `provider_admin_handlers.go:291,112` | AI gateway at runtime | `ReadAPIKeyFile(path)` | `ai.ProviderConfig.APIKeyFile` → `providers/anthropic.go:121` |
| **Gemini Key** | `/etc/security-automation-go/secrets/gemini_api_key` | raw key (provider UI) / `GEMINI_API_KEY=<val>` (wizard) | Provider admin UI | `provider_admin.go:79`, `provider_admin_handlers.go:291,112` | AI gateway at runtime | `ReadAPIKeyFile(path)` | `ai.ProviderConfig.APIKeyFile` → `providers/gemini.go:121` |
| **Admin Password** | SQLite — `ui_settings` table, key `admin_password_hash` | bcrypt hash | Wizard step 2 / password change | `setup_wizard.go:206`, `settings.go:94` | `login.go:56` | `setupStore.GetSetting()` | `uiauth.VerifyPassword()` |
| **Initial Admin Password** | `/etc/security-automation-go/runtime/initial-admin-password` | plaintext (one-time, 32 chars) | Runtime at first start | `ui_runtime.go:74` → `auth/initial_password.go:15` | Operator reads manually | `VerifyInitialPassword(path, candidate)` in `setup_wizard.go:185` | Wizard step 1 login only; truncated after step 2 |
| **UI Session Secret** | `/etc/security-automation-go/secrets/ui_secret` | `UI_SESSION_SECRET=<hex>` | `FileSecretProvider.Ensure()` | `server.go:90` → `secrets.go:105` | `NewFileSecretProvider(cfg.UI.SecretFile)` | File read via `loadLocked()` | HTTP session signing |
| **Admin API Token** | `/etc/security-automation-go/secrets/admin_token` | raw token | Operator (manual) | `config.go:162` (default) | `config.go:450` | `os.ReadFile(AdminTokenFile)` | `GetAdminToken()` → daemon API auth |

---

## Detailed Loading Analysis by Secret

### 1. Cloudflare API Token

**Write path:** `setup_wizard.go:297` defines `cfTokenSecretPath = "/etc/security-automation-go/secrets/cloudflare_api_token"`. Written at `setup_wizard.go:436`:
```go
WriteSecretFile(cfTokenSecretPath, map[string]string{"CF_API_TOKEN": cfToken})
```
File format: `CF_API_TOKEN=<value>` (env-file format).

**Daemon loading:** `deployments/systemd/cf-sync.service`:
```ini
EnvironmentFile=/etc/security-automation-go/secrets/cloudflare_api_token
```
No `-` prefix — mandatory. If the file does not exist, `cf-sync.service` **fails to start**.

systemd injects `CF_API_TOKEN` into the daemon environment. `config.go:256`:
```go
if v := os.Getenv("CF_API_TOKEN"); v != "" {
    cfg.Cloudflare.APIToken = v
}
```

**Fallback:** None. No legacy path. No hardcoded default value. Daemon does not start without this file.

**Verdict:** ✅ Fully canonical. Write path = load path = `/etc/security-automation-go/secrets/cloudflare_api_token`.

---

### 2. AbuseIPDB API Key

**Write path:** `setup_wizard.go:300,499`:
```go
abuseIPDBSecretPath = "/etc/security-automation-go/secrets/abuseipdb_api_key"
WriteSecretFile(abuseIPDBSecretPath, map[string]string{"ABUSEIPDB_KEY": key})
```
File format: `ABUSEIPDB_KEY=<value>` (env-file format).

**Daemon loading:** `config.go:279`:
```go
if v := os.Getenv("ABUSEIPDB_KEY"); v != "" {
    cfg.AbuseIPDB.APIKey = v
}
```
The daemon reads `ABUSEIPDB_KEY` from the environment. The `cf-sync.service` systemd unit has:
```ini
EnvironmentFile=-/etc/security-automation-go/security-automation.env
```
The example file `deployments/config/security-automation.env.example` shows `# ABUSEIPDB_KEY=` (commented out).

The systemd unit does **not** have an `EnvironmentFile` line for `/etc/security-automation-go/secrets/abuseipdb_api_key` directly.

**Gap — see Finding F1 below.**

**Fallback:** None to legacy path. `cfg.AbuseIPDB.APIKey` defaults to `""` (disabled).

**Verdict:** ⚠️ Path is canonical. Loading chain has a structural gap (see F1).

---

### 3. BetterStack Source Token

**Write path:** `setup_wizard.go:301,552`:
```go
betterStackSecretPath = "/etc/security-automation-go/secrets/betterstack_source_token"
WriteSecretFile(betterStackSecretPath, map[string]string{"BETTERSTACK_SOURCE_TOKEN": token})
```

**Daemon loading:** `config.go:368`:
```go
if v := os.Getenv("BETTERSTACK_SOURCE_TOKEN"); v != "" {
    cfg.BetterStack.SourceToken = v
}
```
Same pattern as AbuseIPDB — loaded from env var. The systemd EnvironmentFile for the secret file is not present.

**Fallback:** None to legacy path.

**Verdict:** ⚠️ Path is canonical. Loading chain has a structural gap (same as AbuseIPDB — see F1).

---

### 4–6. AI Provider Keys (OpenAI, Anthropic, Gemini)

**Write paths — two sites:**

| Site | Function | Format |
|------|----------|--------|
| Setup wizard step 7 (`setup_wizard.go:604–618`) | `WriteSecretFile(path, {"OPENAI_API_KEY": val})` | `OPENAI_API_KEY=<value>` |
| Provider admin UI (`provider_admin_handlers.go:112`) | `writeProviderSecret(secretFile, secret)` → `atomicWriteFile(path, []byte(secret), 0o600)` | raw key only |

**Load path — `ai.FromEnv()` in `ai/config.go:45`:**
```go
APIKeyFile: envString("AI_PROVIDER_OPENAI_API_KEY_FILE", ""),
```
Reads the path (not the key itself) from the env var. Default: `""` (provider disabled).

The `configs/ai-providers.example.env` maps this to:
```
AI_PROVIDER_OPENAI_API_KEY_FILE=/etc/security-automation-go/secrets/openai_api_key
```

**Key read — `providers/common.go:23`:**
```go
func ReadAPIKeyFile(path string) (string, error) {
    ...
    data, err := os.ReadFile(path)
    ...
    key := strings.TrimSpace(string(data))
    return key, nil
}
```
Reads **raw file content** — no KEY=VALUE parsing. Verifies `mode & 0o077 == 0` (must be 0600 or stricter).

**UI path — `provider_admin.go:577`:**
```go
func providerSecretPathForName(cfg ai.Config, name AIProviderName) string {
    if strings.TrimSpace(providerCfg.APIKeyFile) != "") {
        return providerCfg.APIKeyFile  // from AI_PROVIDER_*_API_KEY_FILE env var
    }
    _, secretFile, _ := providerSpec(name)  // hardcoded canonical fallback
    return secretFile
}
```
UI falls back to canonical path if env var is not set.

**Fallback:** `providerSpec` hardcodes `/etc/security-automation-go/secrets/` — no legacy path anywhere.

**Verdict:** ✅ Paths are canonical. **See Finding F2** for the wizard format mismatch.

---

### 7. Admin Password Hash

**Write paths:**
- Wizard step 2 (`setup_wizard.go:206`): `setupStore.SetSetting(ctx, "admin_password_hash", hash)`
- Password change (`settings.go:94`): same
- Env-seeded at startup (`ui_runtime.go:97`): same

**Load path:** Login handler (`login.go:56`):
```go
hash, ok, err := s.setupStore.GetSetting(r.Context(), "admin_password_hash")
```

**Storage:** SQLite table `ui_settings`, key `admin_password_hash`. Database at `cfg.StateDir/state.db` = `/var/lib/security-automation-go/state.db`.

**No file path involved.** Not in `/etc/` at all.

**Fallback:** None to any file path.

**Verdict:** ✅ Fully correct. Never stored in a file; always in SQLite.

---

### 8. Initial Admin Password

**Write path:** `ui_runtime.go:74`:
```go
uiauth.GenerateInitialPassword(cfg.UI.InitialPasswordFile)
```
Where `cfg.UI.InitialPasswordFile` defaults to `/etc/security-automation-go/runtime/initial-admin-password` (`config.go:186`). Overridable via `UI_INITIAL_PASSWORD_FILE` env var (`config.go:341`).

**Implementation** (`auth/initial_password.go:15`): Writes 32-char random plaintext via `tmp + rename + chmod 0600`. Idempotent — if file exists and is non-empty, returns existing value.

**Load path:** Wizard step 1 login (`setup_wizard.go:185`):
```go
currentOK := uiauth.VerifyInitialPassword(s.cfg.UI.InitialPasswordFile, currentPwd)
```
`VerifyInitialPassword` reads the file and uses `subtle.ConstantTimeCompare`. Never logs the value.

**Invalidation:** After step 2 (`setup_wizard.go:211`):
```go
_ = uiauth.InvalidateInitialPassword(s.cfg.UI.InitialPasswordFile)
```
Truncates file to empty — inode preserved, content gone.

**Logged:** `ui_runtime.go:77`:
```go
logger.Info("initial setup password available", "path", cfg.UI.InitialPasswordFile)
```
**Only the path is logged. Value is never logged.** ✅

**Fallback:** None to legacy path.

**Verdict:** ✅ Fully canonical.

---

### 9. UI Session Secret

**Write path:** `server.go:90`:
```go
SecretProvider: ui.NewFileSecretProvider(cfg.UI.SecretFile)
```
`cfg.UI.SecretFile` defaults to `/etc/security-automation-go/secrets/ui_secret` (`config.go:185`). Overridable via `UI_SECRET_FILE` env var (`config.go:334`).

`FileSecretProvider.Ensure("UI_SESSION_SECRET")` calls `Set` which calls `WriteSecretFile` — generates a random 32-byte hex token if not already present.

**Load path:** `secrets.go:Lookup` checks `os.Getenv(key)` first (env takes precedence), then reads the backing file (`ui_secret`).

**Fallback:** None to legacy path.

**Verdict:** ✅ Fully canonical.

---

### 10. Admin API Token

**Default path:** `config.go:162`:
```go
AdminTokenFile: "/etc/security-automation-go/secrets/admin_token",
```
Overridable via `CF_SYNC_API_TOKEN_FILE` env var (`config.go:253`).

**Load path:** `config.go:450`:
```go
if c.Global.AdminTokenFile != "" {
    b, err := os.ReadFile(c.Global.AdminTokenFile)
    ...
}
```
Also via env: `CF_SYNC_API_TOKEN` → `cfg.Global.AdminToken` (env takes precedence, `config.go:250`).

**Fallback:** None to legacy path.

**Verdict:** ✅ Fully canonical.

---

## Cross-Layer Verification

### Systemd Units — All EnvironmentFile Paths

| Unit | EnvironmentFile | Type |
|------|----------------|------|
| `cf-sync.service` | `/etc/security-automation-go/secrets/cloudflare_api_token` | mandatory |
| `cf-sync.service` | `-/etc/security-automation-go/security-automation.env` | optional |
| `cf-allowlist-sync.service` | `-/etc/security-automation-go/security-automation.env` | optional |
| `cf-cleanup.service` | `-/etc/security-automation-go/security-automation.env` | optional |
| `crowdsec-sync.service` | `-/etc/security-automation-go/security-automation.env` | optional |
| `cf-shadow.service` | `-/etc/security-automation-go/security-automation.env` | optional |
| `cf-shadow.service` | `/etc/security-automation-go/cf-shadow.env` | mandatory |

All paths canonical. No legacy path in any unit.

### Packaging — Directory Creation

`packaging/deb/DEBIAN/postinst`:
```sh
install -d -m 700 -o security-automation -g security-automation \
    /etc/security-automation-go/secrets
```

`packaging/shared/tmpfiles.d/security-automation-go.conf`:
```
d  /etc/security-automation-go/secrets  0700  security-automation  security-automation
```

Both create canonical path. Legacy path never created by installer.

### Health Checks

`internal/health/checks.go`:
- `CheckPermissions` default: `/etc/security-automation-go/secrets` (`checks.go:192`)
- `CheckLegacyLayout` explicit targets: `/etc/security-automation/secrets` (detection target, not a load path) + `/etc/security-automation-go/secrets` (canonical)

`internal/ui/health_page.go:39,50`:
```go
SecretDir: "/etc/security-automation-go/secrets",
```

### detect Package

`internal/detect/detectors.go:125`:
```go
path = "/etc/security-automation-go/secrets"
```

---

## Findings

### F1 — AbuseIPDB and BetterStack: EnvironmentFile Gap

**Severity:** Medium — functionality, not security. No legacy path involved.

**Observed:** The setup wizard writes:
- `/etc/security-automation-go/secrets/abuseipdb_api_key` → `ABUSEIPDB_KEY=<value>`
- `/etc/security-automation-go/secrets/betterstack_source_token` → `BETTERSTACK_SOURCE_TOKEN=<value>`

The daemon reads `ABUSEIPDB_KEY` and `BETTERSTACK_SOURCE_TOKEN` from the environment via `applyEnvOverrides` (`config.go:279,368`).

The `cf-sync.service` unit does **not** have `EnvironmentFile` lines for these two files. The only env injection is via the optional `security-automation.env`.

**Consequence:** If the operator configured AbuseIPDB or BetterStack via the wizard, the keys are on disk in the correct canonical path — but the daemon will not read them. The daemon sees `cfg.AbuseIPDB.APIKey = ""` and treats AbuseIPDB as unconfigured.

**Resolution (operator action):**
Add to `/etc/security-automation-go/security-automation.env`:
```
ABUSEIPDB_KEY=<value from /etc/security-automation-go/secrets/abuseipdb_api_key>
BETTERSTACK_SOURCE_TOKEN=<value from /etc/security-automation-go/secrets/betterstack_source_token>
```
Or add EnvironmentFile lines to `cf-sync.service` (code change, tracked separately).

**No fallback to legacy path. The gap is structural, not a path issue.**

---

### F2 — Wizard Step 7 Writes AI Keys in env-file Format; ReadAPIKeyFile Reads Raw Content

**Severity:** Medium — functional failure for wizard-configured AI providers. No security issue and no legacy path involved.

**Observed:**

Wizard step 7 (`setup_wizard.go:604–618`):
```go
WriteSecretFile(openAISecretPath, map[string]string{"OPENAI_API_KEY": val})
// writes: OPENAI_API_KEY=sk-proj-abc123 to the file
```

`ReadAPIKeyFile` (`providers/common.go:40–46`):
```go
data, err := os.ReadFile(path)
key := strings.TrimSpace(string(data))
return key, nil
// returns: "OPENAI_API_KEY=sk-proj-abc123" — entire line including prefix
```

The provider would call the OpenAI API with `Authorization: Bearer OPENAI_API_KEY=sk-proj-abc123` which will fail with 401.

**Provider admin UI** (`provider_admin_handlers.go:112`):
```go
writeProviderSecret(secretFile, secret)
// atomicWriteFile(path, []byte(secret), 0o600) — writes raw "sk-proj-abc123"
```
Correct format for `ReadAPIKeyFile`.

**Consequence:** AI providers configured through wizard step 7 will fail to authenticate. The correct management path is the provider admin UI (`/providers`), which writes raw values.

**Resolution (operator action):** If AI keys were configured via the wizard, re-enter them through the provider admin UI. Alternatively, overwrite the file manually:
```bash
echo -n "sk-proj-abc123" | sudo tee /etc/security-automation-go/secrets/openai_api_key
sudo chmod 0600 /etc/security-automation-go/secrets/openai_api_key
```

**Code fix (tracked separately):** Wizard step 7 should call `writeProviderSecret` (raw value write) instead of `WriteSecretFile` (env-file format).

---

## Implicit Fallback Search

**Search performed:** All Go source files scanned for references to `/etc/security-automation/` (without `-go`).

**Result:** Zero implicit fallbacks found in active runtime code.

The string `/etc/security-automation/` appears in active code only in:
- `internal/health/checks.go:273` — `CheckLegacyLayout` explicitly checking for the legacy dir (detection code)
- `internal/health/health.go:33` — code comment explaining `LegacySecretsDir`
- `internal/startuplog/layout_check.go:9` — `DefaultLegacyRoot` constant for detection

None of these are load paths. All three are detection/observation paths that identify the legacy directory so the operator can be alerted.

---

## Summary

| Secret | Path Canonical? | Loaded Correctly? | Finding |
|--------|:--------------:|:-----------------:|---------|
| Cloudflare API Token | ✅ | ✅ | None |
| AbuseIPDB Key | ✅ | ⚠️ | F1 — systemd EnvironmentFile gap |
| BetterStack Token | ✅ | ⚠️ | F1 — systemd EnvironmentFile gap |
| OpenAI Key | ✅ | ⚠️ | F2 — wizard format mismatch (provider UI path is correct) |
| Anthropic Key | ✅ | ⚠️ | F2 — wizard format mismatch (provider UI path is correct) |
| Gemini Key | ✅ | ⚠️ | F2 — wizard format mismatch (provider UI path is correct) |
| Admin Password Hash | ✅ (SQLite) | ✅ | None |
| Initial Admin Password | ✅ | ✅ | None |
| UI Session Secret | ✅ | ✅ | None |
| Admin API Token | ✅ | ✅ | None |

**No secret reads from `/etc/security-automation/` (legacy path) anywhere in active production code.**

Both findings (F1, F2) are pre-existing design issues unrelated to path canonicalization. Neither involves the legacy path. Both are documented here for the first time.
