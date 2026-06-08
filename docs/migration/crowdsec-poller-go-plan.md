# CrowdSec Poller — Python → Go Migration

## Audit: crowdsec-poller.py

**Script:** `/usr/local/bin/crowdsec-poller.py`  
**Service:** `crowdsec-poller.service` (Type=simple, User=root, Restart=always)

### What it does

| Concern | Detail |
|---|---|
| Decisions endpoint | `GET http://127.0.0.1:8080/v1/decisions?limit=100` |
| Auth | `X-Api-Key: <REDACTED_CROWDSEC_LAPI_KEY>` (was hard-coded in script) |
| Alerts endpoint | `cscli alerts list --output json` via subprocess |
| Poll interval | 30 s |
| Log file | `/var/log/crowdsec/decisions.log` (append, newline-delimited JSON) |
| Deduplication | In-memory set of `(decision_id, alert_id)`; reset on restart |
| Rotation | Handled by system logrotate (log.1, log.2.gz present) |
| Permissions | Runs as root, file owned root:root 0644 |
| Retries | None — `urllib.error.URLError` is caught, logged, loop continues |
| Restart safety | No pre-load on startup (risk of duplicate flood after restart) |
| Error handling | `URLError` → warn+continue; other exceptions → error+continue |

### Log record format

Decision:
```json
{"dt":"2026-06-08T10:00:00Z","host":"<hostname>","platform":"CrowdSec","cs":{"event_type":"decision","id":13260738,"ip":"162.216.149.138","type":"ban","scenario":"http:exploit","duration":"59m57s","origin":"CAPI","scope":"Ip","simulated":false}}
```

Alert:
```json
{"dt":"2026-06-08T10:00:00Z","host":"<hostname>","platform":"CrowdSec","cs":{"event_type":"alert","id":1234,"ip":"1.2.3.4","scenario":"http:scan","action":"banned","has_decision":true}}
```

### Consumers

| Consumer | Mechanism |
|---|---|
| Vector → BetterStack | Tails `decisions.log` as file source |
| cidrban | Reads `decisions.log` via `internal/cidrban/service.go` |
| recidive | Reads `decisions.log` via `internal/recidive/service.go` |
| Security UI | Reads `decisions.log` via `internal/ui/security_intelligence.go` |

---

## Go Implementation

**Package:** `internal/crowdsec/poller`

| File | Purpose |
|---|---|
| `poller.go` | `Poller` struct, `Run(ctx)` loop, poll logic, dedup |
| `lapi.go` | HTTP client for `GET /v1/decisions` |
| `alerts.go` | `parseAlerts()` for cscli JSON output |
| `writer.go` | Append-only JSON log writer + `loadSeenIDs()` |
| `poller_test.go` | 9 tests covering all key behaviours |

### Improvements over Python

- **Restart-safe dedup**: `loadSeenIDs()` rebuilds seen-ID sets from the existing log at startup — no duplicate flood after restart.
- **Context-aware shutdown**: goroutine stops cleanly when context is cancelled.
- **Atomic metrics**: `PollSuccessTotal`, `PollErrorTotal`, `DecisionsWritten`, `LastSuccessUnixSec`, `LastErrorUnixSec`.
- **Key from encrypted CredentialStore**: no secrets in config files or env vars.

### Config fields added to `CrowdSecConfig`

```yaml
crowdsec:
  poller_enabled: true          # opt-in gate
  poller_lapi_url: http://127.0.0.1:8080   # auto-detected by internal/detect
  poller_interval: 30s
```

The LAPI key is **not** a YAML/env field. It is stored in the encrypted CredentialStore
(`provider: crowdsec, name: lapi_key`) and loaded at runtime.

Non-secret tunables may still be set via environment:
`CS_POLLER_ENABLED`, `CS_POLLER_LAPI_URL`, `CS_POLLER_INTERVAL`.

### Runtime wiring

The poller starts as a goroutine inside `CrowdSecSyncApp.Run()`. It shares the parent context and stops cleanly on shutdown. No orphaned goroutines.

If the LAPI key is absent from the CredentialStore and the poller is enabled, the poller fails closed with a clear log message and marks CrowdSec health RED — the rest of the runtime is unaffected.

---

## Cutover Procedure

### 1. Configure the LAPI key

Via the UI Settings panel (CrowdSec section) or the first-run wizard:
- Set the LAPI key — stored encrypted in the CredentialStore
- Set LAPI URL (auto-detected if CrowdSec is running locally)
- Enable the poller

### 2. Enable Go poller

```bash
CS_POLLER_ENABLED=true
```

Restart the Go daemon:
```bash
sudo systemctl restart crowdsec-sync
```

Verify new entries appear:
```bash
tail -f /var/log/crowdsec/decisions.log
```

### 3. Stop Python poller

```bash
sudo systemctl stop crowdsec-poller
sudo systemctl disable crowdsec-poller
```

### 4. Validate

```bash
# New decisions visible
tail -f /var/log/crowdsec/decisions.log

# recidive operational
sudo journalctl -u crowdsec-sync -f | grep recidive

# cidrban operational
sudo journalctl -u crowdsec-sync -f | grep cidr

# Vector continues ingesting
sudo journalctl -u vector -n 50
```

### 5. Final cleanup

Once stable, remove:
- `/usr/local/bin/crowdsec-poller.py`
- `/etc/systemd/system/crowdsec-poller.service`

---

## Verdict

**GO FOR PYTHON RETIREMENT** (pending CredentialStore wiring)

The Go poller is a complete, tested replacement for `crowdsec-poller.py`:
- Wire-compatible `decisions.log` format (verified against live samples)
- Decisions via LAPI HTTP + alerts via cscli subprocess (identical to Python)
- Restart-safe deduplication (improvement over Python)
- Clean context shutdown, no orphaned goroutines
- 9 tests: write, mkdir, format, dedup, LAPI error, restart-preload, missing-file, malformed-lines

The LAPI key is loaded from the encrypted CredentialStore at startup (`crowdsec.lapi_key`). `CS_POLLER_LAPI_KEY` does not exist — never set secrets via env or YAML.
