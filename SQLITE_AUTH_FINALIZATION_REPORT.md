# SQLite Auth Finalization Report — Phase 2

**Sprint:** V1.4 Final Hardening  
**Date:** 2026-06-07  
**Status:** COMPLETE

---

## Objective

Remove all file-based admin password storage. Permanent admin credentials now live exclusively in SQLite (`ui_settings` table, key `admin_password_hash`).

---

## Changes Made

### Deleted Files

| File | Reason |
|------|--------|
| `internal/ui/auth/bootstrap.go` | Contained file-based `BootstrapState` JSON persistence (`GetBootstrapState`, `SaveBootstrapState`, `ClearBootstrapState`, `InitializeBootstrapPassword`, `InitializeFromPassword`) — all removed |
| `internal/ui/auth/bootstrap_test.go` | Tests for the above |
| `internal/ui/auth/firstboot_integration_test.go` | Integration tests for file-based bootstrap flow |

### Modified Files

#### `internal/ui/auth/password.go`
- Removed `BootstrapState` struct (was `{IsBootstrap bool, Password string, PasswordHash string}`)
- Retained: `GenerateBootstrapPassword()`, `HashPassword()`, `VerifyPassword()`

#### `internal/config/config.go`
- Removed `AdminPasswordFile` field from `UIBoolConfig`
- Removed default `"/etc/security-automation-go/secrets/admin_password"`
- Removed `UI_ADMIN_PASSWORD_FILE` env override

#### `internal/ui/login.go`
- `handleLoginJSON`: reads `admin_password_hash` from `setupStore.GetSetting`; returns 503 if no store, 401 if hash absent
- Redirect after login: `/` (was `/ui/settings/password`)

#### `internal/ui/settings.go`
- `handleChangePassword`: verifies current password against SQLite hash, stores new hash via `setupStore.SetSetting`

#### `internal/ui/server.go`
- `isBootstrapActive()`: reads `admin_password_hash` from `setupStore`; returns `!ok` (true = no hash set = bootstrap active)
- Removed `auth` import (no longer reads from file)

#### `internal/ui/setup_wizard.go`
- Step 2 POST: verifies against `VerifyInitialPassword` (file) OR existing SQLite hash, then stores new bcrypt hash in SQLite via `SetSetting`, then invalidates the initial password file

#### `cmd/cf-sync/ui_runtime.go`
- Removed `InitializeFromPassword` call
- Added: if `SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD` env var is set and no hash exists in SQLite → bcrypt-hash and store in SQLite
- Never logs the password value

### Test Files Rewritten

| File | Change |
|------|--------|
| `internal/ui/settings_test.go` | New `testAdminStore` in-memory helper; all tests use `newServerWithStore` + pre-seeded hash |
| `internal/ui/auth_integration_test.go` | Full rewrite — uses `testAdminStore`; removed all `InitializeBootstrapPassword`/`GetBootstrapState`/`ClearBootstrapState` |
| `internal/ui/login_test.go` | Full rewrite — direct server construction with `testAdminStore` |
| `internal/ui/mutation_surface_test.go` | Removed bootstrap init lines (nil setupStore → `isBootstrapActive()` = false → no redirect) |
| `internal/ui/server_test.go` | Removed `UI_ADMIN_PASSWORD_FILE` env block |
| `internal/ui/setup_wizard_test.go` | Removed `cfg.UI.AdminPasswordFile` assignment |

---

## Architecture After Phase 2

```
Bootstrap flow:
  1. Initial password written to runtime/initial-admin-password (one-time, 0600)
  2. User reads file, opens setup wizard, enters password
  3. Setup wizard verifies against file (VerifyInitialPassword), hashes new password
  4. New bcrypt hash stored in SQLite: ui_settings["admin_password_hash"]
  5. Initial password file truncated (InvalidateInitialPassword)

Login flow:
  handleLoginJSON → setupStore.GetSetting("admin_password_hash")
    → 503 if no store
    → 401 if key absent or hash empty
    → 401 if VerifyPassword(hash, req.Password) fails
    → 200 + session cookie on success

Password change flow:
  handleChangePassword → verify current password against SQLite hash
    → HashPassword(newPassword) → SetSetting("admin_password_hash", newHash)

Automated deployment:
  SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD env var
    → if no hash in SQLite: HashPassword + SetSetting
    → never logged, never written to file
```

---

## What Is No Longer Present

- `/etc/security-automation-go/secrets/admin_password` file — **eliminated**
- `BootstrapState` JSON file — **eliminated**
- `auth.InitializeBootstrapPassword` — **eliminated**
- `auth.GetBootstrapState` / `auth.ClearBootstrapState` — **eliminated**
- `config.UI.AdminPasswordFile` field — **eliminated**
- `UI_ADMIN_PASSWORD_FILE` env var — **eliminated**

---

## Validation

```
go build ./...          PASS
go test ./...           PASS (all packages)
go test ./internal/ui/... PASS (29.7s)
```

No regressions. The `TestNoMCPRuntimeDependencyStrings` dependency guard passes.

---

## Files Allowed (Bootstrap Path)

The following file is explicitly permitted — it is the one-time bootstrap mechanism:

| Path | Purpose | Lifecycle |
|------|---------|-----------|
| `runtime/initial-admin-password` | First-boot password for wizard setup | Truncated after setup wizard step 2 completes |

This file is mode 0600, written by `uiauth.GenerateInitialPassword`, invalidated by `uiauth.InvalidateInitialPassword` after the admin sets a permanent password.
