# V1.5 Operator Experience Implementation Report

**Date:** 2026-06-07
**Branch:** main
**Head commit:** 69c913e
**Sprint:** Operator Experience — Detection Engine, Health Engine, Health UI, Diagnostic Runner, Support Bundle, Packaging Foundation, Wizard Integration, Dashboard Widgets

---

## Verdict

**COMPLETE**

All 10 phases implemented. Full test suite passes under the race detector. No blockers.

---

## Phase Summary

| Phase | Title | Status | Commit(s) |
|-------|-------|--------|-----------|
| 1 | detect package — core types + probe vars | DONE | 3296aa0 |
| 2 | detect package — 9 full detector implementations | DONE | 43cb558, aab322b |
| 3 | health package — 11 checks (GREEN/YELLOW/RED) | DONE | 924982c, 4853741 |
| 4 | UI Health Center page | DONE | 796a114 |
| 5 | Diagnostic runner + support bundle | DONE | c76c502, 5f731fc |
| 6 | Register routes + nav + dashboard widget | DONE | b881301 |
| 7 | Packaging foundation (.deb/.rpm/sysusers/tmpfiles) | DONE | c6c5ec0 |
| 8 | Wizard integration — detect in step 8 | DONE | 69c913e |
| 9 | Full validation | DONE | — |
| 10 | This report | DONE | — |

---

## Files Changed

### New packages

| File | Purpose |
|------|---------|
| `internal/detect/detect.go` | `Result`, `Config`, `Status`, probe vars (`binaryInstalled`, `fileExists`, `dirWritable`, `systemdServiceActive`), `RunAll`, `ToJSON` |
| `internal/detect/detectors.go` | 9 detector functions |
| `internal/detect/detect_test.go` | 16 tests with probe var overrides |
| `internal/health/health.go` | `Level`, `Check`, `Config`, `RunAll` |
| `internal/health/checks.go` | 11 check functions, `diskStatfs` probe var |
| `internal/health/export_test.go` | Exports `DiskStatfsOverride` for external test package |
| `internal/health/health_test.go` | 30 tests covering all checks and branches |

### New UI files

| File | Purpose |
|------|---------|
| `internal/ui/health_page.go` | `handleHealthPage`, `handleHealthJSON`, `HealthPage`, `buildHealthConfig`, `buildDetectConfig`, render helpers |
| `internal/ui/health_page_test.go` | 4 tests: JSON handler, page handler, component, healthLevelClass |
| `internal/ui/diagnostic.go` | `DiagnosticReport`, `handleRunDiagnostic` |
| `internal/ui/support_bundle.go` | `handleSupportBundle`, `redactSecretLines`, `bundleWriteEntry`, `bundleRunCommand`, `bundleReadTail` |
| `internal/ui/diagnostic_test.go` | 8 tests: method guard, session guard, CSRF guard, JSON response, bundle download, redaction, on-disk persistence |

### Modified UI files

| File | Change |
|------|--------|
| `internal/ui/server.go` | Added 4 routes; extended `dashboardConsoleView()` with `EnvironmentWidget` |
| `internal/ui/types.go` | Added `EnvironmentWidget` struct; added `Environment` field to `DashboardConsoleView` |
| `internal/ui/console.go` | Added "Health" nav item; added Environment & Health dashboard panel |
| `internal/ui/setup_wizard.go` | Injected `detect.RunAll` results into wizard step 8 summary |

### New packaging tree

| File | Purpose |
|------|---------|
| `packaging/deb/DEBIAN/control` | .deb package metadata |
| `packaging/deb/DEBIAN/postinst` | User/dir creation, service enable |
| `packaging/deb/DEBIAN/postrm` | Purge cleanup |
| `packaging/rpm/security-automation-go.spec` | RPM spec with scriptlets |
| `packaging/shared/tmpfiles.d/security-automation-go.conf` | systemd-tmpfiles directory declarations |
| `packaging/shared/sysusers.d/security-automation-go.conf` | systemd-sysusers user/group declarations |
| `PACKAGING_FOUNDATION.md` | Packaging documentation |

---

## New API Endpoints

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/health` | `handleHealthPage` | session + CSRF (middleware chain) |
| GET | `/health/json` | `handleHealthJSON` | session + CSRF (middleware chain) |
| POST | `/health/diagnostic` | `handleRunDiagnostic` | session + CSRF |
| GET | `/health/support-bundle` | `handleSupportBundle` | session |

All routes use the full middleware chain: `setupGuardMiddleware → forcePasswordChangeMiddleware → requireAuthHandler`.

---

## Detection Engine (`internal/detect`)

9 detectors — each returns `Result{Name, Installed, Configured, Healthy, Details}`:

| Detector | Installed condition | Configured condition | Healthy condition |
|----------|---------------------|---------------------|-------------------|
| CrowdSec | `cscli` binary present | decisions log path set | log file exists |
| OpenResty | `openresty` binary present | events file path set | events file exists |
| Nginx | nginx binary present OR log dir exists | log dir set | log dir exists |
| Cloudflare | always true (cloud) | token + zone ID set | same as configured |
| SQLite | always true (embedded) | state dir set | `state.db` file exists |
| Systemd | `systemctl` binary present | same | same |
| StateDir | directory exists | state dir set in cfg | exists AND writable |
| LogDir | directory exists | always | directory exists |
| SecretDir | directory exists | always | exists AND mode `& 0o007 == 0` |

Probe vars (`binaryInstalled`, `fileExists`, `dirWritable`, `systemdServiceActive`) are overridable package-level vars for testing.

---

## Health Engine (`internal/health`)

11 checks — each returns `Check{Name, Status, Reason, Remediation}`:

| Check | GREEN | YELLOW | RED |
|-------|-------|--------|-----|
| Cloudflare | token + zone set | token set, zone missing | token missing |
| AbuseIPDB | key set | enabled but no key | not configured (GREEN) |
| BetterStack | token set or not configured | — | — |
| SQLite | state dir + DB file exist | state dir exists, no DB | state dir missing |
| CrowdSec | decisions log exists | log configured but missing | — |
| OpenResty | events file exists | file configured but missing | — |
| Nginx | log dir exists | log dir missing | — |
| Disk | free ≥ 20% | free 10–20% | free < 10% or < 1 GB |
| Permissions | secrets dir mode `& 0o007 == 0` | dir missing or group-accessible | world-accessible |
| StateDir | dir exists and writable | — | missing or not writable |
| LogDir | dir exists | missing | — |

`diskStatfs` is an overridable var exposed via `internal/health/export_test.go`.

---

## Test Coverage Summary

| Package | Test count | Key coverage |
|---------|-----------|--------------|
| `internal/detect` | 16 | All 9 detectors, all code paths, probe var overrides |
| `internal/health` | 30 | All 11 checks, all severity branches, disk threshold, permission modes |
| `internal/ui` | +12 new tests | Health page, JSON handler, diagnostic (auth guards, CSRF, on-disk), support bundle (auth, gzip), redaction |

---

## Validation Results (Task 9)

| Check | Result |
|-------|--------|
| `gofmt -l .` | Clean — no files need formatting |
| `go vet ./...` | Clean — no issues |
| `go build ./...` | Clean |
| `go test -timeout 120s ./...` | All pass |
| `go test -race -timeout 300s ./...` | All pass — no races |
| `gitleaks` | Not installed on this machine |
| `trufflehog --only-verified` | 1 finding: AbuseIPDB key in `.git/objects/` (git history, pre-existing, not from V1.5 changes) |

The trufflehog finding is in an existing git history object and was not introduced by this sprint. It should be addressed separately (history rewrite or key rotation).

---

## Security Invariants Confirmed

| Invariant | Enforced by |
|-----------|-------------|
| Support bundle requires authentication | `handleSupportBundle` → `s.getSession(r)` |
| Diagnostic endpoint requires session + CSRF | `handleRunDiagnostic` guards |
| Secret values never in support bundle | `redactSecretLines` regex, integer-only `EnvironmentWidget` |
| Tokens/passwords redacted in log tail | `redactSecretLines(content)` on log tail |
| Health/detect result values do not include raw secret values | API keys absent from `health.Config` response fields |

---

## Remaining Gaps

| Gap | Impact | Estimated effort |
|-----|--------|-----------------|
| Packaging not built or tested | `.deb`/`.rpm` files not produced | 1 day to add `make package` + test on clean VM |
| No CI for `.deb`/`.rpm` build | Packaging regressions won't be caught automatically | 0.5 days to add `dpkg-deb` step to CI |
| gitleaks not installed on dev machine | CI scan covers this; local scan gap only | Install: `go install github.com/zricethezav/gitleaks/v8@latest` |
| Support bundle log tail hardcoded to `/var/log/security-automation/cf-sync.log` | Silently empty on dev machines | Minor — `bundleReadTail` handles missing file gracefully |
| `dashboardConsoleView()` calls `detect.RunAll` + `health.RunAll` synchronously on every dashboard load | Could block if `systemctl` is slow | No timeout required by spec; document as known |
| Pre-existing AbuseIPDB key in git history | Secret still valid at time of scan | Rotate key + consider `git filter-repo` to scrub history |
| Config template not packaged | Operators need manual config setup after install | Low priority — documented in `PACKAGING_FOUNDATION.md` |

---

## Commits in This Sprint (newest first)

```
69c913e feat(ui): inject environment detection into wizard step 8 summary
c6c5ec0 feat(packaging): add .deb/.rpm packaging foundation, sysusers, tmpfiles
b881301 feat(ui): register health routes, add Health nav item, add dashboard environment widget
5f731fc fix(ui): add session auth to support bundle, fix redaction separator
c76c502 feat(ui): add diagnostic runner and support bundle handlers
796a114 feat(ui): add Health Center page with detection and health rendering
4853741 fix(health): guard Bsize, fix nginx remediation, add disk/permission branch tests
924982c feat(health): add health package with 11 checks (GREEN/YELLOW/RED)
aab322b test(detect): add missing OpenResty and Nginx detector tests
43cb558 feat(detect): implement all 9 environment detectors with tests
3296aa0 feat(detect): add detect package core types, probe vars, and stubs
```
