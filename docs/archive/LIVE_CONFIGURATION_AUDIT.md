# Live Configuration Audit — cf-sync

**Date:** 2026-06-06  
**Host:** NUC8i3BEH  
**Auditor:** Read-only discovery (no services stopped, no files modified, no secret values printed)

---

## 1. Executive Summary

The `cf-sync` daemon is **active and running** (PID 2750484, uptime ~17 h). It operates in **shadow/dry-run mode** — the startup log confirms `dry_run=true` and the shadow validation report shows 10 081 shadow cycles with 100 % agreement between the Go daemon and the reference Python implementation.

The configuration layout is **hybrid (Layout C)**: the primary config file and the primary secrets env file live in `/etc/security-automation-go/`, while a second secrets env file lives in `/etc/security-automation/secrets/` and a third (optional, currently absent) env file is referenced in `/etc/security-automation/`.

Two anomalies require attention:

1. **`StartLimitIntervalSec` in `[Service]` section** — systemd logs a warning on every reload because `StartLimitIntervalSec` is a `[Unit]` directive; it is silently ignored, so the restart-rate limit is not enforced.
2. **Cloudflare API token rejected (HTTP 401)** — The daemon has been logging `quota refresh failed … Invalid API Token` every 15 minutes since startup. The CF token in the active env file (`/etc/security-automation-go/cf-shadow.env`) is invalid or expired; the daemon continues running and syncing from its cache/shadow state.
3. **`/etc/security-automation/security-automation.env` does not exist** — The unit file references this path with the optional flag (`-`), so the service starts cleanly, but any keys that were expected from that file are silently absent.
4. **`internal/policy/rego/admission.rego` missing** — The daemon logs a warning at every start; the file is not present relative to the working directory `/var/lib/cf-sync`.
5. **Unit file is marked `disabled`** — The service is running (started manually or via a previous enable that was subsequently disabled), but it will not auto-start on boot.

---

## 2. Service Unit

Source: `/etc/systemd/system/cf-sync.service`

```ini
[Unit]
Description=Cloudflare to CrowdSec Reconciliation Daemon
After=network.target crowdsec.service
Wants=crowdsec.service

[Service]
Type=simple
User=root
Group=root

# Secrets — loaded from file, never hard-coded
EnvironmentFile=/etc/security-automation-go/cf-shadow.env
EnvironmentFile=/etc/security-automation/secrets/cf_sync_api_token.env
EnvironmentFile=-/etc/security-automation/security-automation.env

# Paths
StateDirectory=cf-sync
WorkingDirectory=/var/lib/cf-sync

# Execution
ExecStartPre=+/bin/install -d -m 0750 -o root -g root /var/log/security-automation
ExecStart=/usr/local/bin/cf-sync -mode daemon -config /etc/security-automation-go/cf-shadow.yaml -metrics-addr 127.0.0.1:9091

# Reliability
Restart=on-failure
RestartSec=15
StartLimitIntervalSec=300   # <-- WRONG SECTION (should be in [Unit]); silently ignored
StartLimitBurst=5

# Security Hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/lib/cf-sync /var/log/crowdsec /var/log/security-automation

StandardOutput=journal
StandardError=journal
SyslogIdentifier=cf-sync

[Install]
WantedBy=multi-user.target
```

---

## 3. Binary

| Property | Value |
|---|---|
| Path | `/usr/local/bin/cf-sync` |
| Size | 38 MB |
| Permissions | `-rwxr-xr-x` (root:root) |
| Modified | 2026-06-05 23:04 |
| Resolved symlink | `/usr/local/bin/cf-sync` (not a symlink) |
| Embedded version string | None found via `strings` grep on `^v[0-9]+.[0-9]` |
| MainPID | 2750484 |
| `/proc/<pid>/exe` | `/usr/local/bin/cf-sync` |

---

## 4. Active Config File

Path: `/etc/security-automation-go/cf-shadow.yaml`  
Permissions: `-rw-r--r--` (root:root, 343 bytes, created 2026-05-29)

```yaml
version: v1

global:
  service_name: cf-shadow
  log:
    level: info
    format: json

cloudflare:
  zone_id: d2f7807c2c5b7c9737da45f538072423

crowdsec:
  decisions_log: /var/log/crowdsec/decisions.log
  nginx_log_dir: /var/log/nginx
  bin_path: cscli
  timeout: 15s
  allowlist_name: my_allowlist

interval: 60s
state_dir: /var/lib/cf-sync
```

**Keys present:** `version`, `global.service_name`, `global.log.level`, `global.log.format`, `cloudflare.zone_id`, `crowdsec.decisions_log`, `crowdsec.nginx_log_dir`, `crowdsec.bin_path`, `crowdsec.timeout`, `crowdsec.allowlist_name`, `interval`, `state_dir`

**Not present in config:** `ui.bind_address`, `ui.port`, `admin_token`, `admin_token_file` — no UI or API-auth block is configured here; those come from environment variables.

---

## 5. Environment Files

### 5.1 `/etc/security-automation-go/cf-shadow.env`

| Property | Value |
|---|---|
| Exists | Yes |
| Owner | root:root |
| Permissions | `0600` (`-rw-------`) |
| Size | 289 bytes |
| Modified | 2026-05-29 |

**Keys present (values redacted):**

- `CF_API_TOKEN`
- `CF_ZONE_ID`
- `ABUSEIPDB_REPORTING_ENABLED`
- `SHADOW_REPORT_DIR`
- `STATE_DIR`
- `DECISIONS_LOG`
- `NGINX_LOG_DIR`

### 5.2 `/etc/security-automation/secrets/cf_sync_api_token.env`

| Property | Value |
|---|---|
| Exists | Yes |
|  Owner | root:root |
| Permissions | `0600` (`-rw-------`) |
| Size | 83 bytes |
| Modified | 2026-06-05 17:50 |

**Keys present (values redacted):**

- `CF_SYNC_API_TOKEN`

### 5.3 `/etc/security-automation/security-automation.env`

| Property | Value |
|---|---|
| Exists | **No** |
| Unit flag | `-` (optional; failure silently ignored) |

This file is referenced but does not exist. Any variables expected from it are absent.

### 5.4 `/etc/crowdsec/cf-sync.env` (not referenced by unit — informational only)

This file exists (`0600`, root:root, 505 bytes, from a prior configuration iteration) but is **not loaded** by the current unit file.

**Keys it contains (informational):** `CF_API_TOKEN`, `CF_ZONE_ID`, `CS_API_KEY`, `ABUSEIPDB_KEY`, `BETTERSTACK_TOKEN`, `SYNC_ABUSEIPDB`, `CF_NOTIFIER_ACTIVE`

---

## 6. Directories

### 6.1 State Directory

Unit declares: `StateDirectory=cf-sync` → resolves to `/var/lib/cf-sync`  
`WorkingDirectory=/var/lib/cf-sync`

```
/var/lib/cf-sync/
├── 7b8e9c6629df53f0/          # active runtime scope (scope_id from journal)
│   ├── runtime.db             204 KB  (SQLite WAL-mode)
│   ├── runtime.db-shm         32 KB
│   ├── runtime.db-wal         0 bytes (clean checkpoint)
│   ├── runtime_state.json     419 bytes
│   └── security-automation-go.pid
└── shadow/
    ├── PYTHON_GO_PARITY_REPORT.md
    ├── SHADOW_DRIFT_ANALYSIS.md
    └── SHADOW_MODE_REPORT.md
```

Also at root of `/var/lib/cf-sync/`:
- `shadow-cycles.jsonl` — 2.1 MB, last written 2026-06-06 06:47

**SQLite file:** `/var/lib/cf-sync/7b8e9c6629df53f0/runtime.db` — 204 KB

### 6.2 Log Directory

Unit `ExecStartPre` creates `/var/log/security-automation` (`0750`, root:root).

```
/var/log/security-automation/
├── config-check.log    0 bytes  (created 2026-06-05 23:04)
├── healthcheck.log     0 bytes  (created 2026-06-05 23:04)
└── startup.log        152 bytes (created 2026-06-05 23:04)
```

No separate `/var/log/cf-sync/` directory exists.

---

## 7. Network

| Service | Address | Port | Listener Process |
|---|---|---|---|
| cf-sync metrics (Prometheus) | 127.0.0.1 | **9091** | `cf-sync` (pid 2750484) |
| CrowdSec LAPI | 127.0.0.1 | 8080 | `crowdsec` (pid 2198388) |
| mcp-runtime | 127.0.0.1 | 8086 | `mcp-runtime` (pid 2838611) |
| systemd socket unit | 127.0.0.1 | 9090 | systemd |

**UI bind address/port:** Not configured. The config file has no `ui` block and no `UI_PORT` / `UI_BIND_ADDRESS` env key is set in any loaded env file. There is no HTTP UI listener for cf-sync.

**Metrics:** cf-sync exposes Prometheus metrics on `127.0.0.1:9091`, as specified by `-metrics-addr 127.0.0.1:9091` in `ExecStart`.

---

## 8. Startup Log

Path: `/var/log/security-automation/startup.log`

```
2026-06-05T21:04:11Z startup version= mode=daemon bind= config=/etc/security-automation-go/cf-shadow.yaml db=/var/lib/cf-sync dry_run=true providers=[]
```

**Observations:**
- `version=` is empty — binary does not embed a version string accessible to the startuplog package.
- `bind=` is empty — no UI/HTTP bind address configured.
- `dry_run=true` — daemon is running in shadow mode; no writes to Cloudflare.
- `providers=[]` — no providers are registered at startup (runtime scope is in `discovering` lifecycle state per `runtime_state.json`).

Journal entries at last start (2026-06-05 23:04:11 CEST):

```
INFO  "runtime scope initialized" scope_id=7b8e9c6629df53f0 scope_name=cf-shadow/production/shared/d2f7807c2c5b7c9737da45f538072423
WARN  "failed to load default rego policy" error="open internal/policy/rego/admission.rego: no such file or directory"
INFO  "starting in daemon mode" state_dir=/var/lib/cf-sync/7b8e9c6629df53f0 interval=1m0s metrics_addr=127.0.0.1:9091
INFO  "daemon lock acquired" lock_file=/var/lib/cf-sync/7b8e9c6629df53f0/security-automation-go.pid
INFO  "starting stateful multi-worker scheduler" interval=1m0s
```

---

## 9. Secret Sources

| Secret | Source File | Key Name | Notes |
|---|---|---|---|
| Cloudflare API token | `/etc/security-automation-go/cf-shadow.env` | `CF_API_TOKEN` | Currently returning HTTP 401 (invalid/expired) |
| Cloudflare zone ID | `/etc/security-automation-go/cf-shadow.env` | `CF_ZONE_ID` | Also set in config YAML (`cloudflare.zone_id`) |
| cf-sync admin/API token | `/etc/security-automation/secrets/cf_sync_api_token.env` | `CF_SYNC_API_TOKEN` | Used to authenticate calls to cf-sync's own API |
| AbuseIPDB key | **Not loaded** | `ABUSEIPDB_KEY` | Key is in `/etc/crowdsec/cf-sync.env` (not referenced by unit). `ABUSEIPDB_REPORTING_ENABLED` is set in `cf-shadow.env` but the actual key is absent from loaded files |
| BetterStack token | **Not loaded** | `BETTERSTACK_TOKEN` | Key is in `/etc/crowdsec/cf-sync.env` (not referenced by unit) |
| CrowdSec API key | **Not loaded** | `CS_API_KEY` | Key is in `/etc/crowdsec/cf-sync.env` (not referenced by unit) |

**Precedence note:** Environment variables set in later `EnvironmentFile` entries override earlier ones. Load order: `cf-shadow.env` → `cf_sync_api_token.env` → `security-automation.env` (absent). No file-based token-file indirection (`admin_token_file`) was found in the config.

---

## 10. Configuration Layout Verdict

**Layout C — Hybrid**

| Path | Role | Status |
|---|---|---|
| `/etc/security-automation-go/` | Primary config + primary secrets env | Active (2 files) |
| `/etc/security-automation/secrets/` | Secondary secrets env (cf-sync API token) | Active (1 env file + 3 unrelated key files) |
| `/etc/security-automation/` | Optional general env | **Referenced but file absent** |
| `/etc/crowdsec/` | Legacy/parallel config directory | Exists but **not referenced by current unit** |

The system straddles two naming conventions (`security-automation-go` for the Go daemon's own config, `security-automation` for the broader secrets tree) and retains a legacy `/etc/crowdsec/cf-sync.env` from a prior configuration that is now orphaned.

---

## 11. Anomalies / Issues Found

| # | Severity | Location | Issue | Consequence |
|---|---|---|---|---|
| 1 | **High** | Runtime | `CF_API_TOKEN` in `/etc/security-automation-go/cf-shadow.env` is rejected by Cloudflare with HTTP 401 every 15 minutes | Quota tracking is broken; actual IP enforcement through CF WAF may be silently failing |
| 2 | **Medium** | `/etc/systemd/system/cf-sync.service:27` | `StartLimitIntervalSec=300` placed in `[Service]` section instead of `[Unit]` | Restart-rate limit is silently ignored; a crash loop would not be throttled as intended |
| 3 | **Medium** | Unit file | Service is `UnitFileState=disabled` | cf-sync will not start automatically after a reboot |
| 4 | **Medium** | Secret coverage | `ABUSEIPDB_KEY`, `BETTERSTACK_TOKEN`, `CS_API_KEY` are only present in `/etc/crowdsec/cf-sync.env`, which is **not loaded** by the current unit | AbuseIPDB reporting and BetterStack logging are non-functional even if `ABUSEIPDB_REPORTING_ENABLED=true` is set |
| 5 | **Low** | `/etc/security-automation/security-automation.env` | File referenced (with `-` optional flag) but does not exist | Silent; no immediate failure, but intent is unclear |
| 6 | **Low** | Binary | No embedded version string found | `startup.log` reports `version=`; observability tooling cannot identify the deployed version |
| 7 | **Low** | Working directory | `internal/policy/rego/admission.rego` not found relative to `/var/lib/cf-sync` | Rego admission policy is not enforced; daemon continues without it |
| 8 | **Info** | `/var/log/security-automation/` | `config-check.log` and `healthcheck.log` are 0 bytes | Health check and config-check hooks are wired but producing no output |
| 9 | **Info** | `/var/lib/cf-sync/7b8e9c6629df53f0/runtime_state.json` | Lifecycle status is `"discovering"` with epoch fields zeroed | Runtime scope has not progressed past discovery; likely consequence of the invalid CF API token |
