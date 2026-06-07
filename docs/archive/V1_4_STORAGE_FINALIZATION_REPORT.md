# V1.4 Storage Finalization Report

**Date:** 2026-06-07  
**Phase:** 1 of 12 — Storage finalization  
**Status:** COMPLETE

---

## Objective

Replace all references to the deprecated state root `/var/lib/cf-sync` with the v1.4 canonical state root `/var/lib/security-automation-go`. No migration helpers, no fallback. Fail clearly if the new layout is absent.

---

## Changes Applied

### Go Source

| File | Change |
|------|--------|
| `internal/config/config.go:217` | `StateDir` default: `/var/lib/cf-sync` → `/var/lib/security-automation-go` |
| `internal/config/config_ui_test.go` | Test env `UI_SECRET_FILE` and assertion: `/var/lib/cf-sync/secrets.local` → `/var/lib/security-automation-go/secrets.local` |
| `cmd/cf-shadow/main.go` | Usage comment: `--report-dir /var/lib/cf-sync` → `/var/lib/security-automation-go` |

### Systemd Units

| File | Change |
|------|--------|
| `deployments/systemd/cf-sync.service` | `StateDirectory=cf-sync` → `security-automation-go`; `RuntimeDirectory=cf-sync` → `security-automation-go`; `WorkingDirectory` and `Environment=STATE_DIR` and `ReadWritePaths` → `/var/lib/security-automation-go` |
| `deployments/shadow/cf-shadow.service` | `--report-dir` and `ReadWritePaths` → `/var/lib/security-automation-go` |

### Shell Scripts

| File | Change |
|------|--------|
| `deployments/shadow/install-shadow.sh` | `STATE_DIR` → `/var/lib/security-automation-go/shadow` |

### Documentation

| File | Change |
|------|--------|
| `docs/INSTALL_LAYOUT.md` | Directory tree and permissions table |
| `docs/FIRST_BOOT.md` | Reset command for `runtime.db` |
| `docs/runbooks/RUNBOOK.md` | `UI_SECRET_FILE` example |
| `docs/runbooks/CUTOVER_RUNBOOK.md` | Shadow report path, env file block, YAML config block, systemd unit snippet, AbuseIPDB DB path |
| `docs/runbooks/SHADOW_RUNBOOK.md` | All shadow report paths and disk usage command |

### Historical Records (Not Modified)

The following contain `/var/lib/cf-sync` but are preserved as-is (historical forensic records):

- `docs/archive/REPOSITORY_INTEGRITY_REPORT.md`
- `docs/archive/SHADOW_LAUNCH_CHECKLIST.md`
- `LOGGING_ROTATION_AND_DYNAMICUSER_FIX_REPORT.md`
- `SYSTEMD_CONSOLIDATION_REPORT.md`

---

## Systemd StateDirectory Note

`StateDirectory=security-automation-go` instructs systemd to manage `/var/lib/security-automation-go/` — created automatically with correct ownership for `DynamicUser=yes`. The explicit `WorkingDirectory` and `Environment=STATE_DIR` are kept for compatibility with the Go binary's `STATE_DIR` override path in `internal/config/config.go:379`.

The old `StateDirectory=cf-sync` would have pointed systemd to `/var/lib/cf-sync/`. With `DynamicUser=yes`, the directory is owned by the dynamically allocated UID. No migration of the systemd-managed dir is needed — systemd creates it fresh on next start.

---

## Validation

```
go vet ./...        ✅  No issues
go build ./...      ✅  Clean build
grep /var/lib/cf-sync in *.go, *.service, *.sh   ✅  Zero matches
```

---

## Production Cutover Note

On the live host:

```bash
sudo systemctl stop cf-sync
sudo install -d -m 0750 /var/lib/security-automation-go
# Copy or migrate SQLite database if preserving state:
sudo cp -a /var/lib/cf-sync/<scope>/ /var/lib/security-automation-go/<scope>/
sudo systemctl daemon-reload
sudo systemctl start cf-sync
```

**Do not restart services automatically.  
Do not perform production cutover automatically.**
