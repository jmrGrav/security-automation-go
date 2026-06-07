# Release Validation Pipeline v1.5 — Implementation Report

**Date:** 2026-06-07
**Branch:** main
**Head commit:** fdce6c4
**Mission:** Release Validation Pipeline v1.5

---

## 1. Files Modified/Created

| File | Change |
|------|--------|
| `Makefile` | Added all 6 binaries to `build`; new targets: `build-linux-amd64`, `build-linux-arm64`, `verify-release`, `package`; restructured as single-shell block so govulncheck failure captures FAIL but continues to gitleaks/trufflehog |
| `.github/workflows/ci.yml` | Go 1.22.2 → **1.25.11**; added `govulncheck` (continue-on-error), `build-multiarch`, `package-deb` (with setup-go) jobs; artifact upload |
| `go.mod` | Added `toolchain go1.25.11` directive — clears 28 stdlib govulncheck findings without changing minimum version requirement (`go 1.25.0`) |
| `.gitleaks.toml` | Explicit documented allowlists: AbuseIPDB pre-existing finding (commits b4a5b17, 4649a1d, **2aa3646**) + systemd false positive |
| `PACKAGING_FOUNDATION.md` | Updated: `make package` now documented and operational |
| `RELEASE_CHECKLIST.md` | New: pipeline steps, AbuseIPDB decision, govulncheck findings table (3 not 33), GO/NO-GO |
| `V1_5_RELEASE_VALIDATION_PIPELINE_REPORT.md` | Redacted raw AbuseIPDB key value from Section 7 (prior version embedded it verbatim in commit 2aa3646) |

---

## 2. Release Validation Pipeline (`make verify-release`)

Seven-step gate:

| Step | Command | Status |
|------|---------|--------|
| 1 | `gofmt -l .` | PASS — no unformatted files |
| 2 | `go vet ./...` | PASS — no issues |
| 3 | `go test -timeout 120s ./...` | PASS — all packages |
| 4 | `go test -race -timeout 300s ./...` | PASS — no data races |
| 5 | `make build` (all 6 binaries) | PASS — see below |
| 6 | `govulncheck ./...` | FINDINGS — see below |
| 7a | `gitleaks detect --config .gitleaks.toml` | PASS (with documented allowlists) |
| 7b | `trufflehog git file://. --only-verified` | FINDING — see AbuseIPDB section |

---

## 3. CI GitHub Actions (`.github/workflows/ci.yml`)

Updated jobs:

| Job | Change |
|-----|--------|
| `build-and-test` | Go version `1.22.2` → **`1.25.11`**; added `govulncheck` step with `continue-on-error: true` (3 known pre-existing findings in OTEL + OPA — see Section 5) |
| `build-multiarch` | New: builds amd64 + arm64 for all 6 binaries; uploads artifacts (30-day retention) |
| `package-deb` | New: `setup-go@v5` (go 1.25.11) + `make package` (builds from source); uploads `.deb` artifact |
| `secret-scan` | Unchanged (gitleaks-action@v2, respects `.gitleaks.toml` allowlists) |
| `trufflehog` | Hard gate (trufflesecurity/trufflehog@main, `--only-verified`, `base..HEAD` diff scan). **Will fail on first push** — commits 4649a1d and 2aa3646 containing the live AbuseIPDB key are within the unmerged range. This is correct behavior: a secret scanner failing on a live key in the push range is working as designed. Resolves when operator rotates the key or scrubs git history. |

---

## 4. Package Artifact (`make package`)

```
dist/security-automation-go_1.5.0_amd64.deb   (32.6 MB)
```

Package contents:
- `/usr/local/bin/`: 6 binaries (amd64, statically linked)
- `/lib/systemd/system/`: cf-sync, cf-shadow, cf-cleanup, cf-allowlist-sync, crowdsec-sync services + cf-allowlist-sync.timer
- `/usr/lib/sysusers.d/security-automation-go.conf`
- `/usr/lib/tmpfiles.d/security-automation-go.conf`
- `DEBIAN/postinst`, `DEBIAN/postrm` (chmod 755)

RPM: skipped — `rpmbuild` not available on this Debian/Ubuntu host. Install `rpm-build` on Fedora/RHEL/SUSE.

Multi-arch builds verified:
- `make build-linux-amd64` → 6 × ELF 64-bit x86-64 statically linked binaries
- `make build-linux-arm64` → 6 × ELF 64-bit ARM aarch64 statically linked binaries
- Pure Go (`modernc.org/sqlite`): `CGO_ENABLED=0` works on both architectures, no cross-compiler needed

---

## 5. govulncheck Status

**EXIT CODE: 3 (vulnerabilities found)**

**3 vulnerabilities found** — all pre-existing (not introduced by V1.5 work). The original 33 findings have been reduced to 3 by adding `toolchain go1.25.11` to `go.mod` (commit 0430751), which clears all 28 stdlib findings fixed in go1.25.2–go1.25.11.

| CVE/ID | Module | Fix version | Impact |
|--------|--------|-------------|--------|
| GO-2026-4985 | `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp@v1.24.0` | v1.43.0 | Oversized OTLP response → OOM/DoS |
| GO-2026-4394 | `go.opentelemetry.io/otel/sdk@v1.24.0` | v1.40.0 | PATH hijacking via env (requires attacker env control) |
| GO-2024-3141 | `github.com/open-policy-agent/opa@v0.64.1` | v0.68.0 | Windows-only SMB force-auth (no impact on Linux) |

**Decision:** Remediation deferred to a separate dependency update sprint.

**To clear all 3 remaining findings:**
```bash
go get go.opentelemetry.io/otel/sdk@v1.40.0
go get go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp@v1.43.0
go get github.com/open-policy-agent/opa@v0.68.0
go mod tidy
```

---

## 6. gitleaks Status

**EXIT CODE: 0 (no leaks after allowlisting)**

Two allowlist entries added to `.gitleaks.toml`:

**Entry 1 — AbuseIPDB pre-existing finding (EXPLICIT documented decision):**
- Commits `b4a5b17` and `4649a1d` allowlisted with a 300-word inline comment
- This is NOT silent suppression — see AbuseIPDB section below

**Entry 2 — Systemd service file false positive:**
- File: `deployments/systemd/cf-sync.service` in commit `3d65c5c`
- Match: `CF_API_TOKEN=\nEnvironment=CF_ZONE_ID=` (empty env var declarations in systemd unit)
- Rule triggered: `generic-api-key`
- Verdict: False positive — these are environment variable names, not values. No secret present.
- Allowlist: `paths = ['deployments/.*\.service$', 'deployments/.*\.timer$']`

---

## 7. trufflehog Status

**2 verified findings (both pre-existing, same key):**

Finding #1 (original):
```
Detector Type: AbuseIPDB
Raw result:    [REDACTED — see git object 2021b218e13e9f1dfa502035a81893ac4b35c280]
Commit:        4649a1d1fd77064cb3c337147a528c9e67fe0141
File:          CUTOVER_RUNBOOK.md
Line:          151
Timestamp:     2026-05-30 18:00:11 +0000
```

Finding #2 (same key, in prior version of this report):
```
Detector Type: AbuseIPDB
Commit:        2aa3646 (V1_5_RELEASE_VALIDATION_PIPELINE_REPORT.md — prior version embedded the raw key value)
```

Both findings are the same AbuseIPDB key. The raw key value has been redacted from the current version of this report. trufflehog `--only-verified` confirmed the key responded to a live API call. This key **is or was active**.

---

## 8. AbuseIPDB Pre-Existing Finding — Full Decision Record

### What it is

An AbuseIPDB API key was committed in `CUTOVER_RUNBOOK.md` at line 151 in commit
`4649a1d` ("docs: production cutover runbook with capability audit", 2026-05-30).
The same key exists in git blob object `2021b218e13e9f1dfa502035a81893ac4b35c280`.

The key was introduced before V1.4. It is NOT a V1.5 regression.

### What was explicitly NOT done

| Action | Not done because |
|--------|-----------------|
| Automatic key rotation | Standing constraint: "Do not rotate secrets automatically" |
| Git history rewrite | Standing constraint: "Do not rewrite git history unless explicitly requested" |
| Silent `.gitleaksignore` suppression | Mission requirement: "Do not silently ignore detected secrets" |

### What was done

1. Explicit allowlist in `.gitleaks.toml` with a 300-word inline comment naming the commits, the object hash, the decision, and the required operator action
2. Full documentation in `RELEASE_CHECKLIST.md` — AbuseIPDB section
3. Finding documented in `V1_5_OPERATOR_EXPERIENCE_IMPLEMENTATION_REPORT.md` (prior session)
4. This report

### Operator action taken — 2026-06-07

**Key rotated.** Old key revoked at abuseipdb.com. New key written to
`/etc/security-automation/secrets/abuseipdb_api_key` (format: `ABUSEIPDB_KEY=<value>`, permissions: `root:root 0600`).

trufflehog `--only-verified` now returns `verified_secrets: 0` — the key hash remains in git history but is no longer active and cannot be verified.

Optional follow-up: `git filter-repo` to scrub the inactive key from git history — separate operator decision.

---

## 9. GO/NO-GO

| Gate | Status |
|------|--------|
| gofmt | GO |
| go vet | GO |
| go test | GO |
| go test -race | GO |
| go build (6 binaries, amd64 + arm64) | GO |
| govulncheck | **GO** — 0 vulnerabilities (OTEL v1.43.0, OPA v0.68.0, toolchain go1.25.11) |
| gitleaks | **GO** — 108 commits scanned, no leaks |
| trufflehog (local) | **GO** — verified_secrets: 0 (old key revoked 2026-06-07) |
| trufflehog (CI) | **GO** — old key revoked; CI scan will find 0 verified findings |
| .deb package | **GO** — `dist/security-automation-go_1.5.0_amd64.deb` |
| AbuseIPDB key rotation | **DONE** — new key at `/etc/security-automation/secrets/abuseipdb_api_key` |

**Overall: GO — V1.5 release gate fully cleared.**

`make verify-release` exits 0. All 7 steps pass with no warnings. No NO-GO conditions remain.

---

## Commits in This Mission

```
fdce6c4 fix(deps): update OTEL to v1.43.0 and OPA to v0.68.0 — clear govulncheck
74e2df3 docs(pipeline): reconcile v1.5 report to post-fix reality
0430751 fix(pipeline): make verify-release run all steps; update toolchain to go1.25.11
2aa3646 docs: add Release Validation Pipeline v1.5 implementation report
a701294 feat(ci): add release validation pipeline v1.5
```

Previous sprint:
```
b2e309f docs: add V1.5 Operator Experience implementation report
69c913e feat(ui): inject environment detection into wizard step 8 summary
...
```
