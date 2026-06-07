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

### Required operator actions

- [ ] **Rotate the AbuseIPDB API key** — generate a new key at abuseipdb.com and update
  `/etc/security-automation-go/secrets/` and any CI secrets. Do this before production deployment.
- [ ] **Consider `git filter-repo` history scrub** — removes the key from git history so it can
  no longer be extracted by scanning tools. Requires explicit operator decision and coordination
  with all repository clones.

### GO/NO-GO decision

**CONDITIONAL GO** — the release pipeline passes with the documented exception in `.gitleaks.toml`.

This is acceptable **only if**:
1. The operator rotates the AbuseIPDB key before deploying to production
2. The rotation is confirmed before the service starts using the old key

Without key rotation: **NO-GO for production deployment**.

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

**Current status:** 3 known pre-existing vulnerabilities (exit 3).

| Vulnerability | Module | Fix version | Impact |
|---------------|--------|-------------|--------|
| GO-2026-4985 (DoS) | `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp@v1.24.0` | v1.43.0 | Oversized OTLP response bodies → OOM |
| GO-2026-4394 (RCE) | `go.opentelemetry.io/otel/sdk@v1.24.0` | v1.40.0 | PATH hijacking via env (requires attacker env control) |
| GO-2024-3141 (SMB auth) | `github.com/open-policy-agent/opa@v0.64.1` | v0.68.0 | Windows-only SMB force-auth (no impact on Linux) |

All 28 stdlib findings from `go1.25.0` are cleared by the `toolchain go1.25.11` directive in `go.mod`.
Remaining 3 findings require dependency updates (deferred — separate sprint).

`make verify-release` prints the findings as WARN and continues to gitleaks/trufflehog before failing.
CI (`build-and-test`) runs govulncheck with `continue-on-error: true`.

---

## Operator Deployment Steps (NOT automated)

Per standing constraints, the following are manual operator steps:

- [ ] `systemctl daemon-reload`
- [ ] `systemctl restart cf-sync`
- [ ] Verify `/ui/dashboard` loads
- [ ] Confirm health page at `/health` is GREEN
- [ ] Rotate AbuseIPDB key (see above)

---

## Release Gate Summary

| Gate | Status | Notes |
|------|--------|-------|
| gofmt | PASS | All files formatted |
| go vet | PASS | No issues |
| go test | PASS | All tests pass |
| go test -race | PASS | No data races |
| go build (all 6 binaries) | PASS | amd64 + arm64 |
| govulncheck | 3 findings (OTEL + OPA) | NO-GO for production; stdlib cleared by go1.25.11 |
| gitleaks | CONDITIONAL PASS | AbuseIPDB allowlisted with documented decision |
| trufflehog | 2 findings (same key) | Both in .gitleaks.toml allowlist; rotate key before production |
| .deb package | PASS | `dist/security-automation-go_1.5.0_amd64.deb` |
| RPM package | SKIP | `rpmbuild` not available on Debian/Ubuntu hosts |
| Key rotation | OPERATOR ACTION REQUIRED | Rotate AbuseIPDB key |

**Overall: CONDITIONAL GO** — passes for pre-production validation.
**Production deploy: NO-GO until AbuseIPDB key is rotated.**
