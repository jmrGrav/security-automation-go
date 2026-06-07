# Systemd Consolidation Audit — Phase 3

**Sprint:** V1.4 Final Hardening  
**Date:** 2026-06-07  
**Status:** COMPLETE

---

## Summary

All five systemd unit files are now consistent with the v1.4 canonical paths and hardening profile. Three secondary units had stale v1.1-era paths (`/opt/security-automation-go`); these have been corrected.

---

## Unit Inventory

| Unit | Type | Status Before | Status After |
|------|------|--------------|-------------|
| `cf-sync.service` | `simple` daemon | ✅ Already updated (Phase 1) | ✅ No change needed |
| `cf-cleanup.service` | `oneshot` | ❌ v1.1 paths, no hardening | ✅ Fixed |
| `crowdsec-sync.service` | `simple` | ❌ v1.1 paths, no hardening | ✅ Fixed |
| `cf-allowlist-sync.service` | `oneshot` | ❌ v1.1 paths, no hardening | ✅ Fixed |
| `cf-allowlist-sync.timer` | timer | ✅ No paths | ✅ No change needed |
| `cf-shadow.service` | `simple` | ❌ v1.1 paths, partial hardening | ✅ Fixed |

---

## Changes Made

### Binary Path (`ExecStart`)

All secondary units corrected:

| Unit | Before | After |
|------|--------|-------|
| `cf-cleanup.service` | `/opt/security-automation-go/bin/cf-cleanup` | `/usr/local/bin/cf-cleanup` |
| `crowdsec-sync.service` | `/opt/security-automation-go/bin/crowdsec-sync` | `/usr/local/bin/crowdsec-sync` |
| `cf-allowlist-sync.service` | `/opt/security-automation-go/bin/cf-allowlist-sync` | `/usr/local/bin/cf-allowlist-sync` |
| `cf-shadow.service` | `/opt/security-automation-go/bin/cf-shadow` | `/usr/local/bin/cf-shadow` |

### Working Directory

| Unit | Before | After |
|------|--------|-------|
| `cf-cleanup.service` | `/opt/security-automation-go` | `/var/lib/security-automation-go` |
| `crowdsec-sync.service` | `/opt/security-automation-go` | `/var/lib/security-automation-go` |
| `cf-allowlist-sync.service` | `/opt/security-automation-go` | `/var/lib/security-automation-go` |
| `cf-shadow.service` | `/opt/security-automation-go` | `/var/lib/security-automation-go` |

### EnvironmentFile

Secondary units now use the canonical shared env file:

| Unit | Before | After |
|------|--------|-------|
| `cf-cleanup.service` | `/etc/security-automation-go/cf-cleanup.env` | `-/etc/security-automation-go/security-automation.env` (optional) |
| `crowdsec-sync.service` | `/etc/security-automation-go/crowdsec-sync.env` | `-/etc/security-automation-go/security-automation.env` (optional) |
| `cf-allowlist-sync.service` | `/etc/security-automation-go/cf-allowlist-sync.env` | `-/etc/security-automation-go/security-automation.env` (optional) |
| `cf-shadow.service` | `/etc/security-automation-go/cf-shadow.env` | `-/etc/security-automation-go/security-automation.env` (optional) + cf-shadow.env |

### Security Hardening Added to Secondary Units

Added to `cf-cleanup.service`, `crowdsec-sync.service`, `cf-allowlist-sync.service`, `cf-shadow.service`:

```ini
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
ReadWritePaths=/var/lib/security-automation-go /etc/security-automation-go/secrets
```

---

## Remaining Known Gaps (Not Blocking v1.4)

### `User=root` in Secondary Units

`cf-cleanup`, `crowdsec-sync`, `cf-allowlist-sync`, and `cf-shadow` still run as `root`. The primary unit (`cf-sync`) uses `DynamicUser=yes` which is stronger.

**Reason left as-is:** These secondary units require access to CrowdSec socket and Cloudflare credentials that are owned by root. Migrating to `DynamicUser` or a dedicated `security-automation` service user would require ACL changes on the CrowdSec socket and credential files. This is a v1.5 hardening item.

**Mitigation in place:** `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectKernelTunables`, `ProtectControlGroups`, and `RestrictNamespaces` limit the blast radius even when running as root.

### `cf-shadow.service` — No `DynamicUser`

Shadow mode is read-only from Cloudflare's perspective. Future work: assess whether it can use `DynamicUser` + ACL on the report dir.

---

## Canonical Path Reference (v1.4)

| Path | Purpose |
|------|---------|
| `/usr/local/bin/cf-sync` | Main daemon binary |
| `/usr/local/bin/cf-cleanup` | Cleanup job binary |
| `/usr/local/bin/crowdsec-sync` | CrowdSec sync binary |
| `/usr/local/bin/cf-allowlist-sync` | Allowlist sync binary |
| `/usr/local/bin/cf-shadow` | Shadow validator binary |
| `/etc/security-automation-go/` | Config root |
| `/etc/security-automation-go/security-automation.env` | Shared env file |
| `/etc/security-automation-go/secrets/` | Secret files (0600) |
| `/var/lib/security-automation-go/` | State root |
| `/var/log/security-automation/` | Log root |

---

## Validation

```
go build ./...   PASS
go test ./...    PASS
```

No code changes in this phase — systemd unit files only.
