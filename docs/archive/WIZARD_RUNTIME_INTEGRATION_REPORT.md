# Wizard→Runtime Integration Report

**Date:** 2026-06-06
**Sprint:** V1.2 Configuration Consolidation
**Purpose:** Document the disconnect between settings stored by the setup wizard (in SQLite) and the values the runtime actually uses. Specify the exact code fix for `cmd/cf-sync/ui_runtime.go` and clarify which settings require no fix.

---

## Problem Statement

The setup wizard writes operator-provided configuration to the `ui_settings` SQLite table. At runtime, `runUI` in `cmd/cf-sync/ui_runtime.go` reads `cfg.UI.Addr` and `cfg.UI.MutationsEnabled` from the struct populated by YAML/env — it never reads from SQLite. The wizard's outputs are write-only from the runtime's perspective. This directly contradicts the config precedence documented in `docs/INSTALL_LAYOUT.md`:

> 4. SQLite UI settings (`ui_settings` table — applied at runtime, not at startup)

---

## Wizard Step → SQLite → Runtime Mapping

| Setting | Written in Wizard | SQLite Key | Runtime Consumer | Applied? | Impact |
|---------|------------------|-----------|-----------------|---------|--------|
| UI bind address | Step 3 | `ui_addr` | `runUI` → `net.SplitHostPort(cfg.UI.Addr)` | ❌ Never | Service binds original YAML/env address after restart |
| CF token path | Step 4 | `cf_token_path` | None (display only in step 8 summary) | ❌ Never | Stored as a reference, daemon reads directly from EnvironmentFile |
| CF zone ID | Step 4 | `cf_zone_id` | None | ❌ Never | Stored but never passed to daemon; Phase 2+ enhancement |
| Dry-run flag | Step 9 | `dry_run` | N/A (daemon flag, not UI flag) | ✓ By design | See below — no fix needed |
| Mutations enabled | Step 9 | `mutations_enabled` | `runUI` → `cfg.UI.MutationsEnabled` | ❌ Never | Mutations remain disabled regardless of wizard step 9 |

---

## Root Cause

In `cmd/cf-sync/ui_runtime.go`, the `runUI` function:

1. Initializes the setup database via `sqlite.NewSetupStore(setupDB)`
2. Calls `net.SplitHostPort(cfg.UI.Addr)` — using the config struct value
3. Passes `cfg` to `ui.NewServer(cfg, ...)`

The config struct (`cfg`) is populated from YAML and environment variables before `runUI` is called. SQLite is opened but only used to check wizard completion state — it is never queried for `ui_settings` overrides.

The fix is minimal: after the `setupStore` is initialized, read the two relevant keys from SQLite and override the in-memory config struct before any downstream consumers see it.

---

## Fix Specification

### File: `cmd/cf-sync/ui_runtime.go`

**Location:** After `setupStore := sqlite.NewSetupStore(setupDB)` is initialized, and BEFORE `net.SplitHostPort(cfg.UI.Addr)` and `ui.NewServer(cfg, ...)` are called.

**Insert the following block:**

```go
// Apply wizard settings as runtime overrides.
// These are written by the setup wizard and take precedence over YAML/env config,
// consistent with the config precedence documented in docs/INSTALL_LAYOUT.md.
if v, ok, err := setupStore.GetSetting(ctx, "ui_addr"); err == nil && ok && v != "" {
    cfg.UI.Addr = v
}
if v, ok, err := setupStore.GetSetting(ctx, "mutations_enabled"); err == nil && ok && v == "true" {
    cfg.UI.MutationsEnabled = true
}
```

**Important ordering constraints:**
- These overrides MUST happen BEFORE `net.SplitHostPort(cfg.UI.Addr)` — that call uses `cfg.UI.Addr` and will use the YAML/env value if the override is not applied first.
- These overrides MUST happen BEFORE `ui.NewServer(cfg, ...)` — the server struct captures `cfg` at construction time.
- The `ctx` here is the same context passed to `runUI`; no new context is needed.

**Error handling:**
The three-return `GetSetting(ctx, key)` signature returns `(value string, ok bool, err error)`. The condition `err == nil && ok && v != ""` means:
- `err == nil` — no database error
- `ok` — the key exists in the table
- `v != ""` — the value is non-empty

If the key is missing (first boot, before wizard ran) or the database has an error, the config struct value is used as-is. This is the correct fallback — the service must start even without wizard settings.

**Do not panic or fatal on SQLite read errors here.** A best-effort override is appropriate; the service should not fail to start because a settings key is absent.

---

## Dry-Run: No Fix Needed

`dry_run` is written to SQLite in wizard step 9, but this is the correct architecture. Here is why:

- `-dry-run` is a **daemon mode** CLI flag. The daemon (`-mode daemon`) reads it from the command line at startup.
- The UI server (`-mode ui`) does not run syncs and does not have a dry-run concept.
- Wizard step 9 is a **UI confirmation screen** that sets `mutations_enabled=true` for the UI server. The wizard's step 9 wording ("enable production mode") refers to the UI's ability to trigger mutations, not the daemon's sync behavior.
- The daemon's dry-run mode is controlled by its own `-dry-run` flag and YAML config, loaded independently of the wizard.

`dry_run=false` in SQLite is thus a historical artifact of the step 9 design. It is not harmful to store it, but it should not be read by the runtime. The daemon's dry-run setting and the UI's `mutations_enabled` setting are distinct orthogonal flags.

**Correct architecture:**

| Setting | Controls | Set By |
|---------|---------|--------|
| `cfg.Daemon.DryRun` | Whether cf-sync syncs actually modify Cloudflare | Daemon CLI flag `-dry-run`, YAML `daemon.dry_run` |
| `cfg.UI.MutationsEnabled` | Whether the UI permits write operations | Wizard step 9 → SQLite `mutations_enabled` → runtime override (fix above) |

---

## CF Zone ID: Phase 2+ Enhancement

`cf_zone_id` is stored in SQLite by wizard step 4 but never applied. This is out of scope for V1.2 because:

1. The daemon reads the zone ID from the YAML config or environment variable `CF_ZONE_ID`
2. Wiring the SQLite zone ID into the daemon's config requires either:
   - The UI server to write it to the env file at step 9 (write-through pattern), OR
   - The daemon to read from SQLite on startup (cross-mode SQLite read)
3. Both approaches require cross-cutting changes beyond the scope of a configuration consolidation sprint

**Document this gap explicitly** for the V1.3 backlog. The wizard's step 8 summary should note that the zone ID stored in step 4 requires a manual `CF_ZONE_ID=` entry in `/etc/security-automation/security-automation.env` to take effect for the daemon.

---

## CF Token Path Setting: No Runtime Fix Needed

`cf_token_path` is stored in SQLite by wizard step 4 (display only in step 8 summary). The UI runtime does not need to read this value because:

- The daemon loads the CF token via its EnvironmentFile, not via a path stored in SQLite
- The UI does not use the CF token directly
- `cf_token_path` in SQLite is informational only (shows the operator where the token was written)

After the F1 fix (EnvironmentFile path correction), the token written by the wizard at the canonical path will be loaded by the daemon correctly. No SQLite read needed for this field.

---

## Testing the Fix

After applying the code fix to `cmd/cf-sync/ui_runtime.go`, verify:

```bash
# 1. Start the UI, complete the wizard steps 3 and 9
#    - In step 3: change the bind address to 127.0.0.1:9092 (different from default)
#    - In step 9: check the "enable production mode" box

# 2. Stop the UI
sudo systemctl stop cf-sync-ui  # or kill the manual process

# 3. Restart the UI
sudo systemctl start cf-sync-ui  # or run manually

# 4. Verify the service binds 9092 (not 9091)
sudo ss -tlnp | grep cf-sync   # should show 9092

# 5. Verify mutations_enabled is active
#    Check the UI's settings page — "Production mode" should show as enabled
```

A minimal integration test can also verify this by:
1. Writing `ui_addr=127.0.0.1:9099` to the SQLite `ui_settings` table
2. Calling `runUI` with `cfg.UI.Addr = "127.0.0.1:9091"` (default)
3. Asserting the server binds `127.0.0.1:9099`

---

## Summary of Required Code Changes

| File | Change | Phase |
|------|--------|-------|
| `cmd/cf-sync/ui_runtime.go` | Add SQLite override for `ui_addr` and `mutations_enabled` after `setupStore` init | Phase 1 (blocker) |
| No other files | `dry_run`, `cf_token_path`, `cf_zone_id` require no runtime changes in V1.2 | — |
