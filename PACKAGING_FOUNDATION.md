# Packaging Foundation

**Status:** Foundation complete. Packages not yet built.

## Layout

packaging/
├── deb/
│   └── DEBIAN/
│       ├── control      — package metadata
│       ├── postinst     — user/dir creation, service enable
│       └── postrm       — purge cleanup
├── rpm/
│   └── security-automation-go.spec
└── shared/
    ├── tmpfiles.d/security-automation-go.conf  — systemd-tmpfiles
    └── sysusers.d/security-automation-go.conf  — systemd-sysusers

## System User

Name: `security-automation`  
Home: `/var/lib/security-automation-go`  
Shell: `/usr/sbin/nologin`

## Directory Ownership

| Path | Mode | Owner |
|------|------|-------|
| `/var/lib/security-automation-go` | 0750 | security-automation |
| `/var/lib/security-automation-go/diagnostics` | 0750 | security-automation |
| `/etc/security-automation-go/secrets` | 0700 | security-automation |
| `/var/log/security-automation` | 0755 | security-automation |

## Build Steps (not automated yet)

```bash
# .deb (requires dpkg-deb)
dpkg-deb --build packaging/deb security-automation-go_1.5.0_amd64.deb

# .rpm (requires rpmbuild)
rpmbuild -bb packaging/rpm/security-automation-go.spec

# tar.gz install
install -Dm 755 bin/cf-sync /usr/local/bin/cf-sync
install -Dm 644 deployments/systemd/cf-sync.service /lib/systemd/system/cf-sync.service
sh packaging/deb/DEBIAN/postinst configure
```

## Gaps Remaining

- No automated `make package` target yet
- No signing infrastructure
- No repository publication (APT/YUM)
- Config template (`/etc/security-automation-go/security-automation.yaml.example`) not packaged
