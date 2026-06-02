# Shadow Runbook

## Purpose

Run the `security-automation-go` shadow validator while the Python daemon
remains authoritative. This runbook is read-only: no new providers, no new
mutation paths, and no new shadow-status runtime mode.

## Services Involved

- `cf-shadow.service` - Go shadow validator. This is the service to start for
  the shadow run.
- `crowdsec-sync.service` - supporting Go service for CrowdSec state
  observation/sync; keep it in the existing deployment posture.
- `cf-allowlist-sync.timer` - read-only allowlist sync cadence; keep it on the
  existing schedule if already deployed.
- `cf-cleanup.service` - cleanup helper. During shadow, use dry-run only.
- `cf-sync.service` - main Go authority path for later cutover. Keep it stopped
  and disabled during the shadow run unless you are explicitly rehearsing
  authority promotion.
- `crowdsec-cf-sync.service` - Python legacy authority, if still present on the
  host. This remains the authority during shadow.

## Environment and Config Files

- `/etc/security-automation-go/cf-shadow.env` - shadow environment file.
- `/etc/security-automation-go/cf-shadow.yaml` - shadow runtime config.
- `/etc/security-automation-go/crowdsec-sync.env` - environment for the
  CrowdSec sync service, if used by the host deployment.
- `/etc/security-automation-go/cf-cleanup.env` - environment for cleanup, if
  the host uses the installed cleanup unit.
- `/etc/security-automation-go/cf-allowlist-sync.env` - environment for the
  allowlist sync service, if the host uses the installed timer/service pair.
- `/var/lib/cf-sync/secrets.local` - UI secret file used by `cf-sync -mode ui`.

Provider-specific AI config is environment-only and fail-closed:

- `AI_EXPLAIN_ENABLED`
- `AI_PROVIDER_OPENAI_ENABLED`
- `AI_PROVIDER_OPENAI_API_KEY_FILE`
- `AI_PROVIDER_ANTHROPIC_ENABLED`
- `AI_PROVIDER_ANTHROPIC_API_KEY_FILE`
- `AI_PROVIDER_GEMINI_ENABLED`
- `AI_PROVIDER_GEMINI_API_KEY_FILE`

## Build the Binaries

```bash
GOTOOLCHAIN=go1.25.0 go build ./cmd/cf-sync
GOTOOLCHAIN=go1.25.0 go build ./cmd/cf-shadow
GOTOOLCHAIN=go1.25.0 go build ./cmd/security-automation-mcp
```

## Start Shadow

Recommended install path:

```bash
sudo install -d -m 0755 /etc/security-automation-go
sudo install -d -m 0755 /opt/security-automation-go/bin
sudo install -m 0640 deployments/shadow/cf-shadow.env.example /etc/security-automation-go/cf-shadow.env
sudo install -m 0644 deployments/shadow/cf-shadow.yaml.example /etc/security-automation-go/cf-shadow.yaml
sudo install -m 0644 deployments/shadow/cf-shadow.service /etc/systemd/system/cf-shadow.service
sudo systemctl daemon-reload
sudo systemctl enable --now cf-shadow.service
```

If the deployment also manages the supporting read-only services on this host,
bring them up in the same maintenance window without promoting Go authority:

```bash
sudo systemctl enable --now crowdsec-sync.service
sudo systemctl enable --now cf-allowlist-sync.timer
```

The cleanup helper must remain dry-run only during shadow:

```bash
GOTOOLCHAIN=go1.25.0 go run ./cmd/cf-cleanup --dry-run
```

## Stop Shadow

```bash
sudo systemctl stop cf-shadow.service
sudo systemctl disable cf-shadow.service
sudo systemctl daemon-reload
```

Do not start `cf-sync.service` during rollback unless you are explicitly moving
to authority rehearsal.

## Verify Python Remains Authority

Python authority is considered present if the legacy daemon is still active:

```bash
systemctl status crowdsec-cf-sync.service --no-pager
journalctl -u crowdsec-cf-sync.service --no-pager -n 100
```

If the Python service is absent, do not promote Go automatically. Treat that as
a deployment issue and restore the legacy authority path first.

## Verify Go Remains Read-Only Shadow

```bash
systemctl status cf-shadow.service --no-pager
journalctl -u cf-shadow.service --no-pager -n 100
grep -E '^(CF_API_TOKEN|CF_ZONE_ID|STATE_DIR|CLOUDFLARE_MUTATIONS_ENABLED|AI_EXPLAIN_ENABLED|AI_PROVIDER_.*_ENABLED)=' /etc/security-automation-go/cf-shadow.env
test -f /var/lib/cf-sync/shadow/SHADOW_MODE_REPORT.md && tail -n 20 /var/lib/cf-sync/shadow/SHADOW_MODE_REPORT.md
```

Expected posture:

- Go reports `SHADOW MODE: Go will compute plans but NOT mutate Cloudflare`.
- No Cloudflare write path is active from the shadow unit.
- Shadow report files continue to advance.

## Verify Cloudflare Mutations Are Disabled

```bash
grep -E '^CLOUDFLARE_MUTATIONS_ENABLED=0$' /etc/security-automation-go/cf-shadow.env
grep -E '^mutations_enabled: false$' /etc/security-automation-go/cf-shadow.yaml
systemctl status cf-cleanup.service --no-pager || true
```

Also confirm the UI mutation gate remains off:

```bash
rg -n 'MutationsEnabled|handleCloudflareBanPreview|ui mutations disabled|cloudflare mutations disabled' internal/ui internal/config -g '!vendor/**'
```

## Verify CrowdSec Write Boundary Is Unchanged

During shadow, no new CrowdSec writer may appear in AI, MCP, or UI layers:

```bash
rg -n 'cscli|allowlist|ban|deban|decision|write|mutat' internal/ai internal/mcpserver internal/ui cmd/security-automation-mcp -g '!vendor/**'
systemctl status crowdsec-sync.service --no-pager
systemctl status cf-allowlist-sync.timer --no-pager
```

The goal is to keep the existing CrowdSec boundary exactly as it was before the
shadow launch.

## Inspect the UI Operator Console

Start the local UI if needed:

```bash
GOTOOLCHAIN=go1.25.0 go run ./cmd/cf-sync -config /etc/security-automation-go/cf-sync.yaml -mode ui
```

Useful read-only checks:

```bash
curl -skI http://127.0.0.1:9090/
curl -skI http://127.0.0.1:9090/providers
curl -skI http://127.0.0.1:9090/audit
curl -skI http://127.0.0.1:9090/timeline
curl -skI http://127.0.0.1:9090/intelligence
curl -skI http://127.0.0.1:9090/trusted-networks
curl -skI http://127.0.0.1:9090/cloudflare/diff
curl -skI http://127.0.0.1:9090/replay
curl -skI http://127.0.0.1:9090/recovery
curl -skI http://127.0.0.1:9090/drift
```

To inspect AI Explain gating from the UI, use an unauthenticated POST and
expect CSRF/auth failure when the gate is working:

```bash
curl -sk -X POST http://127.0.0.1:9090/ui/ai/explain \
  -H 'Content-Type: application/json' \
  -d '{"subject_type":"provider","subject_id":"cloudflare","provider_preference":"auto"}'
```

If AI providers are disabled, the `/providers` page should show masked keys and
disabled provider state. If a provider is enabled, the provider config must be
backed by its `AI_PROVIDER_*_API_KEY_FILE` path and must never print the raw
key.

## Inspect MCP

The MCP entrypoint is stdio-first and read-only:

```bash
timeout 3s GOTOOLCHAIN=go1.25.0 go run ./cmd/security-automation-mcp
GOTOOLCHAIN=go1.25.0 go test ./internal/mcpserver
GOTOOLCHAIN=go1.25.0 go test ./internal/mcpserver -run 'TestServerExposesReadOnlyTools|TestServerRedactsSecrets|TestServerRejectsForbiddenImports' -v
```

Expected posture:

- The process starts on stdio.
- Only read-only tools are registered.
- The audit sink redacts secrets.

## Inspect AI Explain State

Check the environment-driven provider posture:

```bash
grep -E '^(AI_EXPLAIN_ENABLED|AI_PROVIDER_OPENAI_ENABLED|AI_PROVIDER_OPENAI_API_KEY_FILE|AI_PROVIDER_ANTHROPIC_ENABLED|AI_PROVIDER_ANTHROPIC_API_KEY_FILE|AI_PROVIDER_GEMINI_ENABLED|AI_PROVIDER_GEMINI_API_KEY_FILE)=' /etc/security-automation-go/cf-shadow.env
```

Then inspect the UI provider page:

```bash
curl -skI http://127.0.0.1:9090/providers
```

Expected result:

- AI Explain is disabled by default if `AI_EXPLAIN_ENABLED` is unset or false.
- Missing provider secrets keep the provider disabled.
- No raw provider key is rendered in the UI or logs.

## Metrics to Watch

- `journalctl -u cf-shadow.service`
- `journalctl -u crowdsec-sync.service`
- `journalctl -u cf-allowlist-sync.timer`
- `journalctl -u cf-cleanup.service`
- `/var/lib/cf-sync/shadow/SHADOW_MODE_REPORT.md`
- `/var/lib/cf-sync/shadow/PYTHON_GO_PARITY_REPORT.md`
- `/var/lib/cf-sync/shadow/SHADOW_DRIFT_ANALYSIS.md` if present
- `du -sh /var/lib/cf-sync /var/lib/cf-sync/shadow`

Watch for:

- agreement percentage
- false positives and false negatives
- report growth
- unexpected drift class changes
- shadow process restarts

## Logs to Watch

- `journalctl -u cf-shadow.service --no-pager -n 100`
- `journalctl -u crowdsec-sync.service --no-pager -n 100`
- `journalctl -u cf-cleanup.service --no-pager -n 100`
- `journalctl -u cf-allowlist-sync.service --no-pager -n 100` if the host uses
  a service unit instead of a timer
- `/var/lib/cf-sync/shadow/SHADOW_MODE_REPORT.md`
- `/var/lib/cf-sync/shadow/PYTHON_GO_PARITY_REPORT.md`

## Rollback Procedure

If the shadow run needs to stop:

```bash
sudo systemctl stop cf-shadow.service
sudo systemctl disable cf-shadow.service
sudo systemctl daemon-reload
```

Then confirm the Python authority path is still available:

```bash
systemctl status crowdsec-cf-sync.service --no-pager
```

Do not delete the report directory unless you are intentionally discarding the
shadow evidence.

## Final Operator Note

GO SHADOW.
