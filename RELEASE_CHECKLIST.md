# Release Checklist — security-automation-go

This checklist must be completed before any production deployment or tagged release.
All items must reach a documented state (PASS, SKIP with justification, or OPERATOR ACTION REQUIRED).

---

## Pre-Release Tool Requirements

Install these tools before running `make verify-release`:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/zricethezav/gitleaks/v8@latest
# trufflehog: https://github.com/trufflesecurity/trufflehog#installation
```

---

## Pipeline Steps (`make verify-release`)

| Step | Command | Expected result |
|------|---------|-----------------|
| 1 | `gofmt -l .` | No output (all files formatted) |
| 2 | `go vet ./...` | No output (no issues) |
| 3 | `go test -timeout 120s ./...` | All tests pass |
| 4 | `go test -race -timeout 300s ./...` | All tests pass, no races |
| 5 | `go build` (all 6 binaries) | Binaries built to `bin/` |
| 6 | `govulncheck ./...` | No vulnerabilities |
| 7a | `gitleaks detect --config .gitleaks.toml` | No new findings (pre-existing AbuseIPDB entry is allowlisted — see below) |
| 7b | `trufflehog git file://. --only-verified` | Pre-existing AbuseIPDB finding — see below |

---

## AbuseIPDB Pre-Existing Finding

**THIS IS A KNOWN OPEN FINDING. It is NOT suppressed silently.**

### What was found

`trufflehog git file://. --only-verified` reports a verified AbuseIPDB API key in git history (2 findings, same key):

| # | Commit | File | Note |
|---|--------|------|------|
| 1 | `4649a1d` | `CUTOVER_RUNBOOK.md:151` | Original introduction |
| 2 | `2aa3646` | `V1_5_RELEASE_VALIDATION_PIPELINE_REPORT.md` | Prior version of report embedded the raw key value; current version redacted |

Also present in `b4a5b17` via the same git blob object.

- **Git object:** `.git/objects/20/21b218e13e9f1dfa502035a81893ac4b35c280`
- **trufflehog verdict:** `--only-verified` confirmed the key responded to a live API check
- **Sprint introduced:** Commit `4649a1d` pre-dates V1.4 and V1.5; commit `2aa3646` was V1.5 report documentation

### What was NOT done (and why)

| Action | Status | Reason |
|--------|--------|--------|
| Automatic key rotation | NOT performed | Standing constraint: "Do not rotate secrets automatically" |
| `git filter-repo` history scrub | NOT performed | Standing constraint: "Do not rewrite git history unless explicitly requested" |
| Silent suppression (`.gitleaksignore`) | NOT done | Mission requirement: "Do not silently ignore detected secrets" |

### What WAS done

- The raw key value has been **redacted** from `V1_5_RELEASE_VALIDATION_PIPELINE_REPORT.md` HEAD
- All affected commits are **explicitly allowlisted** in `.gitleaks.toml` with a full decision record comment (commits `b4a5b17`, `4649a1d`, `2aa3646`)
- The finding is **explicitly documented** in this checklist

### Operator actions — status 2026-06-07

- [x] **Rotate the AbuseIPDB API key** — DONE. Old key revoked at abuseipdb.com.
  New key written to `/etc/security-automation/secrets/abuseipdb_api_key`
  (format: `ABUSEIPDB_KEY=<value>`, `root:root 0600`).
  trufflehog `--only-verified` now returns `verified_secrets: 0`.
- [ ] **Consider `git filter-repo` history scrub** — removes the inactive key from git history.
  Separate operator decision; not blocking since the key is revoked.

### GO/NO-GO decision

**GO** — key rotated, trufflehog clean, all pipeline gates pass.

`make verify-release` exits 0 as of commit fdce6c4.

---

## Multi-Architecture Build

```bash
make build-linux-amd64    # produces bin/linux-amd64/
make build-linux-arm64    # produces bin/linux-arm64/
```

All 6 binaries use `modernc.org/sqlite` (pure Go) — `CGO_ENABLED=0` works on both
architectures without a cross-compiler.

| Binary | amd64 | arm64 |
|--------|-------|-------|
| `crowdsec-sync` | ✓ | ✓ |
| `cf-allowlist-sync` | ✓ | ✓ |
| `cf-cleanup` | ✓ | ✓ |
| `cf-sync` | ✓ | ✓ |
| `cf-shadow` | ✓ | ✓ |
| `security-automation-mcp` | ✓ | ✓ |

---

## Packaging (`make package`)

```bash
make package VERSION=1.5.0
```

- **Output:** `dist/security-automation-go_1.5.0_amd64.deb`
- **.deb contents:** all 6 binaries, 5 systemd units + timer, sysusers.d, tmpfiles.d
- **RPM:** skipped if `rpmbuild` is not installed (install `rpm-build` package on Fedora/RHEL/SUSE)

### dpkg-deb verification

After building the .deb:

```bash
dpkg-deb --info dist/security-automation-go_1.5.0_amd64.deb
dpkg-deb --contents dist/security-automation-go_1.5.0_amd64.deb
```

---

## Go Vulnerability Check

```bash
govulncheck ./...
```

**Current status: PASS — 0 vulnerabilities (exit 0). As of 2026-06-07.**

All findings cleared:
- 28 stdlib findings cleared by `toolchain go1.25.11` in `go.mod` (commit 0430751)
- 3 third-party findings cleared by dep updates (commit fdce6c4):
  - GO-2026-4985: `otlptracehttp` → v1.43.0
  - GO-2026-4394: `otel/sdk` → v1.43.0
  - GO-2024-3141: `opa` → v0.68.0

`make verify-release` step 6 exits 0 with no warnings.
CI (`build-and-test`) govulncheck step has `continue-on-error: true` retained for defence-in-depth.

---

## Operator Deployment Steps (NOT automated)

Per standing constraints, the following are manual operator steps:

- [ ] `systemctl daemon-reload`
- [ ] `systemctl restart cf-sync`
- [ ] Verify `/ui/dashboard` loads
- [ ] Confirm health page at `/health` is GREEN
- [x] Rotate AbuseIPDB key — DONE 2026-06-07

---

## Release Gate Summary

| Gate | Status | Notes |
|------|--------|-------|
| gofmt | PASS | All files formatted |
| go vet | PASS | No issues |
| go test | PASS | All tests pass |
| go test -race | PASS | No data races |
| go build (all 6 binaries) | PASS | amd64 + arm64 |
| govulncheck | **PASS — 0 findings** | OTEL v1.43.0, OPA v0.68.0, toolchain go1.25.11 |
| gitleaks | PASS | 108 commits, no leaks |
| trufflehog | **PASS — 0 verified** | Old key revoked 2026-06-07; inactive hash in history is not a finding |
| .deb package | PASS | `dist/security-automation-go_1.5.0_amd64.deb` |
| RPM package | SKIP | `rpmbuild` not available on Debian/Ubuntu hosts |
| Key rotation | **DONE** | New key at `/etc/security-automation/secrets/abuseipdb_api_key` |

**Overall: GO — V1.5 release gate fully cleared. `make verify-release` exits 0.**
