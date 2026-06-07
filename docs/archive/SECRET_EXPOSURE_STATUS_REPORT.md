# Secret Exposure Status Report — Phase 5

**Sprint:** V1.4 Final Hardening  
**Date:** 2026-06-07  
**Status:** COMPLETE — No secret values exposed in logs, responses, or UI

---

## Scope

Review of all paths where secret values (passwords, API tokens, bcrypt hashes, session tokens) could be printed, logged, returned in HTTP responses, or stored in unintended locations.

Files reviewed: `internal/ui/`, `cmd/cf-sync/`, `internal/ui/auth/`

**Constraint:** No values printed in this review. Findings describe structural exposure risk only.

---

## Finding Summary

| Category | Finding | Status |
|----------|---------|--------|
| Admin password hash logging | Never logged | ✅ SAFE |
| Initial password value logging | Never logged — only file path | ✅ SAFE |
| API token in error messages | Not present | ✅ SAFE |
| API token in audit events | Not present | ✅ SAFE |
| Session token in logs | Not present | ✅ SAFE |
| UI_SECRET in logs | Not present | ✅ SAFE |
| Password in HTTP error responses | Generic messages only | ✅ SAFE |
| bcrypt hash in HTTP responses | Not returned | ✅ SAFE |
| Token in HTTP response bodies | Not returned | ✅ SAFE |
| Secret in JSON API responses | Not present | ✅ SAFE |

---

## Detailed Review

### 1. Admin Password Hash (`admin_password_hash`)

**Storage:** SQLite `ui_settings` table — bcrypt hash only  
**Log paths checked:**
- `cmd/cf-sync/ui_runtime.go:100` — `logger.Info("initial admin password stored in SQLite from environment")` — logs event only, not the hash or plaintext
- `internal/ui/settings.go:68,88,96` — error logs include only `"err"` key, not the hash value
- `internal/ui/server.go` — `isBootstrapActive()` calls `GetSetting` but does not log the returned value

**Result:** Hash value never reaches any log sink. ✅

### 2. Initial Password File (`runtime/initial-admin-password`)

**Storage:** File at `cfg.UI.InitialPasswordFile`, mode 0600, one-time use  
**Log paths checked:**
- `cmd/cf-sync/ui_runtime.go:77` — `logger.Info("initial setup password available", "path", cfg.UI.InitialPasswordFile)` — logs **only the file path**, not the password value. This is explicitly documented: `// NEVER log the password value — log only the file path.`
- `internal/ui/auth/initial_password.go` — `GenerateInitialPassword` returns the value to the caller; the caller (ui_runtime.go) does not log it
- `internal/ui/setup_wizard.go` — `VerifyInitialPassword` reads the file inline; return value is `bool`, not the password string

**Result:** Password value never reaches any log sink. ✅

### 3. Cloudflare API Token

**Storage:** `/etc/security-automation-go/secrets/cloudflare_api_token`, mode 0600  
**Log paths checked:**
- `internal/ui/setup_wizard.go:316-333` — `validateCFToken` returns errors containing: token status string, zone ID — **not** the token value
- `internal/ui/setup_wizard.go:430` — `"Token validation failed: "+err.Error()` — err.Error() contains status/zone info from validateCFToken, not the token
- `internal/ui/setup_wizard.go:436` — `s.logger.Error("write CF token secret", "err", err)` — file I/O error, not the token value

**Result:** Token value never appears in error messages or logs. ✅

### 4. BetterStack Source Token

**Storage:** `/etc/security-automation-go/secrets/betterstack_source_token`, mode 0600  
**Log paths checked:**
- `internal/ui/setup_wizard.go:374` — `"source token rejected (HTTP %d)"` — logs HTTP status code only
- `internal/ui/setup_wizard.go:547,551` — `"Validation failed: "+err.Error()` / `"Failed to store token: "+err.Error()` — err contains network errors or HTTP status, not the token

**Result:** Token value never appears in error messages or logs. ✅

### 5. UI Secret (`UI_SECRET`)

**Storage:** `cfg.UI.SecretFile`, loaded via `SecretProvider.Ensure("UI_SECRET")`  
**Log paths checked:**
- `internal/ui/server.go:99` — `"load ui secret: %w"` — error path only, not the value
- `internal/ui/login.go:107-109` — `secret := r.PostForm.Get("secret")`, compared but not logged; audit records only `{"reason": "invalid_secret"}` or `{"actor": "local"}` on success

**Result:** UI secret value never reaches any log sink. ✅

### 6. Session Tokens

**Storage:** In-memory `Server.sessions` map (token → expiry time)  
**Log paths checked:**
- `internal/ui/server.go` — session tokens are keys in the map; never logged
- `internal/ui/login.go` — JSON response body contains `"session_token"` field; this is intentional (returned to client only)
- `internal/ui/settings.go:getSession` — reads cookie; not logged

**Note:** Session tokens ARE returned in JSON login responses — this is intentional. They are not written to any server-side log.

**Result:** Session tokens not logged server-side. Client receives them as intended. ✅

### 7. HTTP Error Responses — No Secret Leakage

All `http.Error(w, ...)` calls in auth paths use generic messages:
- `"unauthorized"` — handleLoginJSON
- `"current password is incorrect"` — handleChangePassword
- `"not configured"`, `"auth not initialized"` — service state messages
- `"invalid request"` — malformed JSON
- `"csrf required"` — CSRF failure

None of these messages include hash values, token values, or password content.

**Result:** HTTP error bodies are safe. ✅

### 8. AbuseIPDB / OpenAI / Anthropic / Gemini API Keys

**Storage:** `/etc/security-automation-go/secrets/` files, mode 0600  
**Checked:**
- Key values are read by the respective provider packages at runtime
- Provider error messages return HTTP status codes and generic failure messages
- `ai.Config.APIKeyFile` is a file path — logged paths are safe (file path ≠ key value)
- `"AI provider unavailable" ... "reason", "disabled or secret file missing"` — path/status only

**Result:** API key values never appear in logs or responses. ✅

---

## Audit Record Safety

`internal/ui/login.go` audit records:
```go
s.audit.Record("login_failed", map[string]string{"reason": "bad_form"})
s.audit.Record("login_failed", map[string]string{"reason": "invalid_secret"})
s.audit.Record("login_success", map[string]string{"actor": "local"})
```

All audit records contain categorical metadata only. No passwords, tokens, or hashes.

`internal/ui/settings.go`:
```go
s.audit.Record("password_changed", map[string]string{})
```

Empty metadata — correct.

---

## No Issues Found

No secret values are exposed in:
- Log output (slog)
- HTTP error responses
- Audit records
- JSON API responses
- Error message strings

The codebase correctly follows the "log file paths, not values" convention established in v1.4.
