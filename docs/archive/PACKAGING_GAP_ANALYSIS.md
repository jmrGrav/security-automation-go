# Packaging Gap Analysis — Phase 10

**Sprint:** V1.4 Final Hardening  
**Date:** 2026-06-07  
**Status:** ANALYSIS ONLY — No packaging implemented in v1.4

---

## Current State

v1.4 ships no packages. Installation is manual (copy binary + install systemd unit). This document identifies what is needed to produce distributable `.deb`, `.rpm`, and `tar.gz` packages.

---

## Common Prerequisites (All Formats)

### 1. Build Pipeline

The binary requires CGO (`mattn/go-sqlite3`). Packaging must handle this:

| Approach | Complexity | Trade-off |
|----------|-----------|-----------|
| Build on each target platform | Low | Requires CI runners per platform |
| Cross-compile with musl | Medium | Static binary, works everywhere |
| Switch to `modernc.org/sqlite` | High | Pure Go, eliminates CGO | 

Recommended: **cross-compile with musl** for `.deb`/`.rpm`; pure Go SQLite for a wider audience.

### 2. Version Injection

The binary needs to embed the version at build time:

```go
// cmd/cf-sync/main.go (not yet implemented)
var Version = "dev"

// Build with:
// go build -ldflags="-X main.Version=v1.4.0" ./cmd/cf-sync/
```

Currently no version embedding exists in `main.go`. This must be added before packaging.

### 3. Postinstall / Pre-Remove Scripts

All package formats need lifecycle scripts:

```
# postinstall
- Create /etc/security-automation-go/ and subdirectories
- Set permissions: secrets/ 0700, runtime/ 0700
- Install systemd unit to /etc/systemd/system/
- systemctl daemon-reload
- Print: "Edit /etc/security-automation-go/security-automation.env, then systemctl enable --now cf-sync"

# pre-remove
- systemctl stop cf-sync || true
- systemctl disable cf-sync || true
- Preserve /etc/security-automation-go/ (config) and /var/lib/security-automation-go/ (state)
  → Do NOT delete these — dpkg/rpm purge logic only, not remove

# purge (debian only)
- Remove /etc/security-automation-go/ if operator explicitly purges
- Warn: "State dir /var/lib/security-automation-go/ preserved — remove manually"
```

---

## `.deb` Package Gap Analysis

### Required Files

| File | Status | Notes |
|------|--------|-------|
| `debian/control` | ❌ Missing | Package metadata (name, version, description, depends) |
| `debian/postinst` | ❌ Missing | Create dirs, install unit, daemon-reload |
| `debian/prerm` | ❌ Missing | Stop and disable service before remove |
| `debian/postrm` | ❌ Missing | Cleanup on purge |
| `debian/conffiles` | ❌ Missing | Mark /etc/ files as conffiles (preserved on upgrade) |
| `debian/copyright` | ❌ Missing | Required for Debian Policy compliance |

### Dependencies

```
Depends: libc6 (>= 2.34)
```

No other runtime dependencies (SQLite is compiled in via CGO).

### Build Command

```bash
dpkg-buildpackage -b -us -uc
# or via nFPM:
nfpm pkg --packager deb --config nfpm.yaml
```

**Recommended tool:** `nfpm` (https://nfpm.goreleaser.com/) — simpler than full debian toolchain.

### Upgrade Handling

`dpkg` preserves conffiles unless the maintainer script explicitly overwrites them. The postinstall script must NOT overwrite `/etc/security-automation-go/secrets/cloudflare_api_token` on upgrade — only create it if absent.

---

## `.rpm` Package Gap Analysis

### Required Files

| File | Status | Notes |
|------|--------|-------|
| `rpmbuild/SPEC/cf-sync.spec` | ❌ Missing | Package spec file |
| `%post` scriptlet | ❌ Missing | Same as postinstall above |
| `%preun` scriptlet | ❌ Missing | Stop service |
| `%postun` scriptlet | ❌ Missing | daemon-reload after remove |

### Dependencies

```
Requires: glibc >= 2.34
```

### Build Command

```bash
rpmbuild -bb rpmbuild/SPEC/cf-sync.spec
# or via nFPM:
nfpm pkg --packager rpm --config nfpm.yaml
```

### SELinux Policy

On RHEL 9 with enforcing SELinux, an `.fc` (file context) policy is needed for `/var/lib/security-automation-go/`. Without it, `DynamicUser=yes` may fail to write to the state directory.

Required additional file:
- `selinux/cf_sync.te` — SELinux type enforcement policy
- `selinux/cf_sync.fc` — file context rules

This is the most significant blocker for RHEL 9 packaging.

---

## `tar.gz` Archive Gap Analysis

The simplest distribution format — no package manager integration.

### Required Structure

```
cf-sync-v1.4.0-linux-amd64.tar.gz
├── bin/
│   └── cf-sync
├── deployments/
│   └── systemd/
│       └── cf-sync.service
├── config/
│   └── security-automation.env.example
└── scripts/
    └── install.sh          ← Manual install script (does not yet exist)
```

### Missing: `scripts/install.sh`

A manual install script is needed that:
1. Copies binary to `/usr/local/bin/`
2. Creates directories with correct permissions
3. Installs systemd unit
4. Runs `systemctl daemon-reload`
5. Prints next steps

This is separate from `deployments/shadow/install-shadow.sh` (shadow-specific).

---

## `nfpm.yaml` Skeleton (Not Yet Created)

If using `nfpm` for both `.deb` and `.rpm`:

```yaml
# nfpm.yaml — NOT YET CREATED
name: cf-sync
arch: amd64
platform: linux
version: "v1.4.0"
maintainer: "Security Automation Team"
description: "Cloudflare-CrowdSec reconciliation daemon with web UI"
license: "MIT"

contents:
  - src: bin/cf-sync
    dst: /usr/local/bin/cf-sync
    file_info:
      mode: 0755
  - src: deployments/systemd/cf-sync.service
    dst: /etc/systemd/system/cf-sync.service
    file_info:
      mode: 0644
  - src: config/security-automation.env.example
    dst: /etc/security-automation-go/security-automation.env
    type: config|noreplace
    file_info:
      mode: 0644

scripts:
  postinstall: scripts/pkg/postinstall.sh
  preremove: scripts/pkg/preremove.sh
  postremove: scripts/pkg/postremove.sh
```

---

## Prioritized Gap List

| Priority | Item | Effort | Blocks |
|---------|------|--------|--------|
| P1 | Version embedding (`-ldflags`) | Small | All formats |
| P1 | `scripts/install.sh` (tar.gz) | Small | tar.gz |
| P1 | `nfpm.yaml` config | Medium | .deb, .rpm |
| P2 | Lifecycle scripts (postinst, prerm) | Medium | .deb, .rpm |
| P2 | CI build step for static binary | Medium | All formats |
| P3 | SELinux policy | Large | RHEL 9 |
| P3 | Debian Policy compliance | Large | Debian repos |

---

## Recommendation

For v1.5, implement in this order:
1. Version embedding (1 day)
2. `scripts/install.sh` + `tar.gz` release via GoReleaser (2 days)
3. `nfpm.yaml` + `.deb` + `.rpm` via GoReleaser (3 days)
4. SELinux policy stub for RHEL 9 (1 day)

Total estimated effort: **~7 developer-days** for a complete packaging pipeline.
