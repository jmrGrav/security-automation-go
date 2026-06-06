# Installer Readiness Report — Phase 8

**Sprint:** V1.4 Final Hardening  
**Date:** 2026-06-07  
**Status:** PARTIAL — Manual install works; no packaged installer yet (see Phase 10 for packaging gap analysis)

---

## Target Platforms

| Platform | Systemd | CGO | SQLite | Status |
|----------|---------|-----|--------|--------|
| Ubuntu 24.04 LTS | ✅ systemd 255 | ✅ glibc 2.39 | ✅ 3.45 | ✅ READY (manual) |
| Debian 13 (Trixie) | ✅ systemd 256 | ✅ glibc 2.40 | ✅ 3.46 | ✅ READY (manual) |
| Fedora 42 | ✅ systemd 257 | ✅ glibc 2.41 | ✅ 3.47 | ✅ READY (manual) |
| RHEL 9 / AlmaLinux 9 | ✅ systemd 252 | ✅ glibc 2.34 | ✅ 3.34 | ✅ READY (manual) |

All four targets are systemd-based and use glibc. No platform-specific blockers.

---

## Manual Install Procedure (All Platforms)

```bash
# 1. Build binary (on build host with Go 1.22+)
go build -o bin/cf-sync ./cmd/cf-sync/

# 2. Copy binary
sudo install -Dm 755 bin/cf-sync /usr/local/bin/cf-sync

# 3. Create config directories
sudo mkdir -p /etc/security-automation-go/secrets
sudo mkdir -p /etc/security-automation-go/backups
sudo chmod 700 /etc/security-automation-go/secrets

# 4. Write Cloudflare API token (required)
sudo install -Dm 600 /dev/null /etc/security-automation-go/secrets/cloudflare_api_token
echo "CF_API_TOKEN=<your-token>" | sudo tee /etc/security-automation-go/secrets/cloudflare_api_token

# 5. Install systemd unit
sudo install -Dm 644 deployments/systemd/cf-sync.service /etc/systemd/system/cf-sync.service
sudo systemctl daemon-reload

# 6. Enable and start (UI mode with setup wizard)
# Edit /etc/security-automation-go/security-automation.env as needed
sudo systemctl enable --now cf-sync
```

State directory (`/var/lib/security-automation-go/`) is created automatically by systemd via `StateDirectory=security-automation-go`.

---

## Platform-Specific Notes

### Ubuntu 24.04 / Debian 13

- `DynamicUser=yes` is fully supported
- `LogsDirectory=security-automation` creates `/var/log/security-automation/`
- `StateDirectory=security-automation-go` creates `/var/lib/security-automation-go/`
- `ProtectSystem=strict` + all hardening directives: fully supported
- No additional packages needed beyond glibc

### Fedora 42 / RHEL 9

- Same systemd capabilities as Debian-based
- SELinux: `ProtectSystem=strict` may need a custom SELinux policy for writing to `/var/lib/security-automation-go/`. On RHEL 9 with enforcing SELinux, test `sudo audit2allow -a` after first run.
- RHEL 9 has SQLite 3.34 — compatible with the WAL journal mode we use
- On RHEL 9, ensure `glibc-devel` is present if building locally

---

## CGO Dependency

The binary requires CGO (`CGO_ENABLED=1`) due to the SQLite driver (`mattn/go-sqlite3`). This means:

1. The binary must be compiled on or for the target architecture
2. Cross-compilation requires a C cross-compiler for the target
3. A statically-linked build is possible but requires `-tags sqlite_omit_load_extension` and a suitable musl toolchain

**Alternative (future):** Switch to `modernc.org/sqlite` (pure Go) to eliminate CGO dependency. Not done in this sprint — see Phase 10 packaging gap analysis.

### Building a Static Binary (for distribution)

```bash
# Ubuntu/Debian build host for Linux AMD64
CGO_ENABLED=1 \
CC=musl-gcc \
go build \
  -tags sqlite_omit_load_extension \
  -ldflags='-linkmode external -extldflags "-static"' \
  -o bin/cf-sync ./cmd/cf-sync/
```

---

## Systemd Unit Compatibility Matrix

| Directive | Ubuntu 24.04 | Debian 13 | Fedora 42 | RHEL 9 |
|-----------|-------------|-----------|-----------|--------|
| `DynamicUser=yes` | ✅ | ✅ | ✅ | ✅ |
| `StateDirectory=` | ✅ | ✅ | ✅ | ✅ |
| `RuntimeDirectory=` | ✅ | ✅ | ✅ | ✅ |
| `LogsDirectory=` | ✅ | ✅ | ✅ | ✅ |
| `ProtectSystem=strict` | ✅ | ✅ | ✅ | ✅ |
| `MemoryDenyWriteExecute=` | ✅ | ✅ | ✅ | ✅ |
| `RestrictAddressFamilies=` | ✅ | ✅ | ✅ | ✅ |
| `RestrictNamespaces=` | ✅ | ✅ | ✅ | ✅ (needs kernel ≥ 5.x) |

All directives supported on systemd ≥ 240, which all four targets meet.

---

## Missing Prerequisites (Blocking Packaged Installer)

| Item | Status | Notes |
|------|--------|-------|
| `.deb` package | ❌ Missing | See Phase 10 |
| `.rpm` package | ❌ Missing | See Phase 10 |
| `tar.gz` archive | ❌ Missing | See Phase 10 |
| Postinstall script | ❌ Missing | Needs to create dirs, set permissions |
| Pre-remove script | ❌ Missing | Needs to stop service, preserve config |
| Upgrade migration | Partial | SQLite migration runs automatically on startup |
| SELinux policy | ❌ Missing | RHEL 9 may need custom policy for state dir |

---

## What Works Today (Manual)

- Fresh install with manual binary placement
- Systemd unit installation and hardening
- First-boot setup wizard
- Upgrade (stop → replace binary → start — migrations auto-run)
- Shadow mode side-car

---

## Verdict

Manual installation is **production-ready** on all four target platforms. Packaged installation (`.deb`, `.rpm`, `tar.gz`) is **not yet available** — Phase 10 documents the gaps.
