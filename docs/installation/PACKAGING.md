# Packaging Foundation

**Status:** Complete. `make package` builds and produces `dist/security-automation-go_VERSION_amd64.deb`.

## Quick Start

```bash
# Build .deb for current version
make package

# Build specific version
make package VERSION=1.5.0

# Result
ls dist/security-automation-go_1.5.0_amd64.deb

# Verify package contents
dpkg-deb --info dist/security-automation-go_1.5.0_amd64.deb
dpkg-deb --contents dist/security-automation-go_1.5.0_amd64.deb
```

## Package Contents

| Path | Contents |
|------|---------|
| `/usr/local/bin/` | 6 binaries: `cf-sync`, `cf-shadow`, `cf-cleanup`, `cf-allowlist-sync`, `crowdsec-sync`, `security-automation-mcp` |
| `/lib/systemd/system/` | 5 service files + `cf-allowlist-sync.timer` |
| `/usr/lib/sysusers.d/` | `security-automation-go.conf` (user/group) |
| `/usr/lib/tmpfiles.d/` | `security-automation-go.conf` (directories) |
| `DEBIAN/postinst` | User/dir creation, default env file, legacy unit removal, `systemctl enable cf-sync` |
| `DEBIAN/prerm` | Stop `cf-sync` before remove/deconfigure |
| `DEBIAN/postrm` | Purge cleanup (dirs, user, group) |

## Packaging Tree

```
packaging/
├── deb/
│   └── DEBIAN/
│       ├── control      — package metadata (Version injected by make package, Architecture: amd64)
│       ├── postinst     — user/dir creation, default env file, service enable (chmod 755)
│       ├── prerm        — stop service before remove (chmod 755)
│       └── postrm       — purge cleanup: dirs, user, group (chmod 755)
├── rpm/
│   └── security-automation-go.spec   — RPM spec with scriptlets
└── shared/
    ├── tmpfiles.d/security-automation-go.conf  — systemd-tmpfiles
    └── sysusers.d/security-automation-go.conf  — systemd-sysusers
```

`make package` assembles binaries and shared files under `packaging/deb/` before calling `dpkg-deb --build`.

## System User

Name: `security-automation`
Home: `/var/lib/security-automation-go`
Shell: `/usr/sbin/nologin`

## Directory Ownership

| Path | Mode | Owner |
|------|------|-------|
| `/var/lib/security-automation-go` | 0750 | security-automation |
| `/var/lib/security-automation-go/runtime` | 0750 | security-automation |
| `/var/lib/security-automation-go/secret.key` | 0600 | security-automation |
| `/etc/security-automation-go/security-automation.env` | 0644 | root |
| `/var/log/security-automation-go` | 0755 | security-automation |

## Multi-Architecture Builds

All binaries use `modernc.org/sqlite` (pure Go) — no CGO, no cross-compiler required.

```bash
make build-linux-amd64   # bin/linux-amd64/
make build-linux-arm64   # bin/linux-arm64/
```

## RPM

RPM packaging requires `rpmbuild` (available on Fedora, RHEL, SUSE):

```bash
# On RPM-based distros:
sudo dnf install rpm-build   # or yum install rpm-build
make package
```

`make package` skips RPM with a message if `rpmbuild` is not found.

## Remaining Gaps

- No package signing infrastructure (GPG signing for APT/YUM repos)
- No repository publication (APT/YUM repo hosting)
- Config template (`/etc/security-automation-go/security-automation.yaml.example`) not packaged
- ARM64 `.deb` not produced by `make package` (uses amd64 binaries); separate `make package ARCH=arm64` target not yet implemented
ge ARCH=arm64` target not yet implemented
