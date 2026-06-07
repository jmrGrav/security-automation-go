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

`trufflehog git file://. --only-verified` reports a verified AbuseIPDB API key in git history:

- **Git object:** `.git/objects/20/21b218e13e9f1dfa502035a81893ac4b35c280`
- **Object type:** blob
- **Introduced by:** Commit `b4a5b17` ("release: v1.1.1 production hardening") and
  `4649a1d` ("docs: production cutover runbook with capability audit")
- **trufflehog verdict:** `--only-verified` confirmed the key responded to a live API check
- **Sprint introduced:** Pre-dates V1.4 and V1.5 — not introduced by any recent work

### What was NOT done (and why)

| Action | Status | Reason |
|--------|--------|--------|
| Automatic key rotation | NOT performed | Standing constraint: "Do not rotate secrets automatically" |
| `git filter-repo` history scrub | NOT performed | Standing constraint: "Do not rewrite git history unless explicitly requested" |
| Silent suppression (`.gitleaksignore`) | NOT done | Mission requirement: "Do not silently ignore detected secrets" |

### What WAS done

- The finding is **explicitly documented** in `.gitleaks.toml` with a commit-specific allowlist entry
  (commits `b4a5b17`, `4649a1d`) and a full comment explaining the decision
- The finding is **explicitly documented** in this checklist
- The finding is reported in `V1_5_OPERATOR_EXPERIENCE_IMPLEMENTATION_REPORT.md`

### Required operator actions

- [ ] **Rotate the AbuseIPDB API key** — generate a new key at abuseipdb.com and update
  `/etc/security-automation-go/secrets/` and any CI secrets. Do this before production deployment.
- [ ] **Consider `git filter-repo` history scrub** — removes the key from git history so it can
  no longer be extracted by scanning tools. Requires explicit operator decision and coordination
  with all repository clones. Command: `git filter-repo --strip-blobs-bigger-than 0B --invert-paths --blob-ids-with-sizes <file>`
  (or use `git filter-repo --strip-blobs-with-ids` with the object hash).

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

Expected: no vulnerabilities in direct or transitive dependencies.
If findings are reported: assess severity, update dependencies, re-run.

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
| govulncheck | Must verify | Run `make verify-release` |
| gitleaks | CONDITIONAL PASS | AbuseIPDB allowlisted with documented decision |
| trufflehog | FINDING (pre-existing) | AbuseIPDB key — rotate before production |
| .deb package | PASS | `dist/security-automation-go_1.5.0_amd64.deb` |
| RPM package | SKIP | `rpmbuild` not available on Debian/Ubuntu hosts |
| Key rotation | OPERATOR ACTION REQUIRED | Rotate AbuseIPDB key |

**Overall: CONDITIONAL GO** — passes for pre-production validation.
**Production deploy: NO-GO until AbuseIPDB key is rotated.**
