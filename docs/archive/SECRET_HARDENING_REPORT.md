# Secret Hardening Report — Phase 4

**Sprint:** V1.4 Final Hardening  
**Date:** 2026-06-07  
**Status:** COMPLETE (CI config + hook template; runtime verification requires tool installation)

---

## Objective

Add gitleaks (pre-commit + CI) and trufflehog (CI) scanning to prevent secrets from entering the repository, and gate releases on a clean secret scan.

---

## What Was Added

### 1. CI Workflow — `.github/workflows/ci.yml`

Two new jobs added to the existing CI pipeline:

#### `secret-scan` (gitleaks)
```yaml
secret-scan:
  name: Secret Scan (gitleaks)
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0
    - name: gitleaks scan
      uses: gitleaks/gitleaks-action@v2
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Scans the full commit history on every push and pull request. Blocks merge on any detected secret.

#### `trufflehog`
```yaml
trufflehog:
  name: Secret Scan (trufflehog)
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0
    - name: trufflehog scan
      uses: trufflesecurity/trufflehog@main
      with:
        path: ./
        base: ${{ github.event.repository.default_branch }}
        head: HEAD
        extra_args: --only-verified
```

Scans new commits using verified-only mode (only secrets confirmed as active credentials are flagged).

### 2. gitleaks Configuration — `.gitleaks.toml`

Extends the default gitleaks ruleset with allow-lists for:
- Test fixture files (`*_test.go`, `testdata/`)
- Documentation with example/placeholder values (`docs/`, `*REPORT.md`, `*RUNBOOK*.md`)
- `.env.example` files

### 3. Pre-commit Hook Installer — `scripts/install-hooks.sh`

Run once after cloning:
```bash
bash scripts/install-hooks.sh
```

This installs a pre-commit hook that runs `gitleaks protect --staged` before every commit. If gitleaks is not installed, the hook prints a warning and exits 0 (non-blocking) to avoid breaking contributors who haven't installed the tool yet.

---

## Release Secret Scan Gate

**Current state:** No automated release process exists in this repository yet (no release workflow, no tag-triggered CI).

**Recommendation for when packaging is implemented (Phase 10):** Add a `release` workflow that:
1. Runs `gitleaks detect --source . --config .gitleaks.toml`
2. Runs `trufflehog filesystem . --only-verified`
3. Only proceeds to build/publish if both exit 0

This gate should be added to the release workflow at the same time the release process is defined.

---

## Tool Installation Status (Local)

| Tool | Installed | Notes |
|------|-----------|-------|
| gitleaks | Not installed | CI uses `gitleaks/gitleaks-action@v2` |
| trufflehog | Not installed | CI uses `trufflesecurity/trufflehog@main` |
| govulncheck | Not installed | Not part of this phase |

Local installation commands:
```bash
# gitleaks (binary from GitHub releases)
GITLEAKS_VERSION=8.18.4
curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks

# trufflehog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

---

## False Positive Risk Assessment

The current codebase contains:
- **Bcrypt hashes in test files** — covered by the `*_test.go` allowlist
- **Path strings resembling credentials** — e.g., `/etc/security-automation-go/secrets/cloudflare_api_token` — these are path references, not values, and should not trigger standard secret detectors
- **No hardcoded API keys or tokens** — confirmed by manual review in Phase 5

Expected false positive rate: low. The `.gitleaks.toml` allowlists are conservative and focused on genuine test/documentation patterns.
