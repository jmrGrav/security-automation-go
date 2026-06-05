# Shadow Launch Checklist

## Pre-Launch

- [ ] Confirm `crowdsec-cf-sync.service` is still active and remains the
      authoritative Python daemon if the host still uses it.
- [ ] Confirm `cf-shadow.service` is installed but not yet active.
- [ ] Confirm `cf-sync.service` is not active during shadow.
- [ ] Confirm `crowdsec-sync.service` and `cf-allowlist-sync.timer` are in the
      expected deployment posture.
- [ ] Confirm `/etc/security-automation-go/cf-shadow.env` exists.
- [ ] Confirm `/etc/security-automation-go/cf-shadow.yaml` exists.
- [ ] Confirm the environment file keeps mutations off:
      `CLOUDFLARE_MUTATIONS_ENABLED=0`.
- [ ] Confirm AI Explain remains fail-closed unless explicitly enabled.
- [ ] Confirm provider key file paths are present only when provider enablement
      is intentional.
- [ ] Confirm `/var/lib/cf-sync/secrets.local` exists for the UI if the local
      operator console will be started.
- [ ] Confirm the shadow report directory is writable:
      `/var/lib/cf-sync/shadow`.

## Launch

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cf-shadow.service
```

If the host also runs the supporting read-only services in the same window:

```bash
sudo systemctl enable --now crowdsec-sync.service
sudo systemctl enable --now cf-allowlist-sync.timer
```

- [ ] `cf-shadow.service` is active.
- [ ] `cf-shadow.service` journal shows the shadow banner.
- [ ] `SHADOW_MODE_REPORT.md` is created in `/var/lib/cf-sync/shadow`.

## Verify Python Remains Authority

```bash
systemctl status crowdsec-cf-sync.service --no-pager
journalctl -u crowdsec-cf-sync.service --no-pager -n 100
```

- [ ] Python daemon is still the authoritative path.
- [ ] Go shadow has not replaced Python authority.

## Verify Go Is Shadow Only

```bash
systemctl status cf-shadow.service --no-pager
journalctl -u cf-shadow.service --no-pager -n 100
grep -E '^(CF_API_TOKEN|CF_ZONE_ID|STATE_DIR|CLOUDFLARE_MUTATIONS_ENABLED|AI_EXPLAIN_ENABLED|AI_PROVIDER_.*_ENABLED)=' /etc/security-automation-go/cf-shadow.env
test -f /var/lib/cf-sync/shadow/SHADOW_MODE_REPORT.md && tail -n 20 /var/lib/cf-sync/shadow/SHADOW_MODE_REPORT.md
```

- [ ] Go shadow is active.
- [ ] Go shadow reports the read-only posture.
- [ ] No Cloudflare mutation is attempted from the shadow unit.

## Verify Cloudflare Mutations Are Disabled

```bash
grep -E '^CLOUDFLARE_MUTATIONS_ENABLED=0$' /etc/security-automation-go/cf-shadow.env
grep -E '^mutations_enabled: false$' /etc/security-automation-go/cf-shadow.yaml
systemctl status cf-cleanup.service --no-pager || true
```

- [ ] Cloudflare mutation toggle is off.
- [ ] Cleanup is dry-run only during shadow.

## Verify CrowdSec Write Boundary Is Unchanged

```bash
rg -n 'cscli|allowlist|ban|deban|decision|write|mutat' internal/ai internal/mcpserver internal/ui cmd/security-automation-mcp -g '!vendor/**'
systemctl status crowdsec-sync.service --no-pager
systemctl status cf-allowlist-sync.timer --no-pager
```

- [ ] No new CrowdSec writer was introduced into AI, MCP, or UI.
- [ ] Supporting services remain in the expected posture.

## Inspect UI Operator Console

```bash
GOTOOLCHAIN=go1.25.0 go run ./cmd/cf-sync -config /etc/security-automation-go/cf-sync.yaml -mode ui
```

Then inspect:

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
curl -sk -X POST http://127.0.0.1:9090/ui/ai/explain \
  -H 'Content-Type: application/json' \
  -d '{"subject_type":"provider","subject_id":"cloudflare","provider_preference":"auto"}'
```

- [ ] UI routes return the expected read-only responses.
- [ ] AI Explain remains gated by auth/CSRF unless the operator has explicitly
      enabled it.
- [ ] Provider health cards mask key material.

## Inspect MCP

```bash
timeout 3s GOTOOLCHAIN=go1.25.0 go run ./cmd/security-automation-mcp
GOTOOLCHAIN=go1.25.0 go test ./internal/mcpserver
GOTOOLCHAIN=go1.25.0 go test ./internal/mcpserver -run 'TestServerExposesReadOnlyTools|TestServerRedactsSecrets|TestServerRejectsForbiddenImports' -v
```

- [ ] MCP starts on stdio.
- [ ] Only read-only tools are registered.
- [ ] Audit sink and redaction tests remain green.

## Inspect AI Explain State

```bash
grep -E '^(AI_EXPLAIN_ENABLED|AI_PROVIDER_OPENAI_ENABLED|AI_PROVIDER_OPENAI_API_KEY_FILE|AI_PROVIDER_ANTHROPIC_ENABLED|AI_PROVIDER_ANTHROPIC_API_KEY_FILE|AI_PROVIDER_GEMINI_ENABLED|AI_PROVIDER_GEMINI_API_KEY_FILE)=' /etc/security-automation-go/cf-shadow.env
curl -skI http://127.0.0.1:9090/providers
```

- [ ] AI Explain is disabled by default unless explicitly enabled.
- [ ] Missing provider secrets keep the provider disabled.
- [ ] No raw provider key is printed by the UI or logs.

## Runtime Smoke

```bash
GOTOOLCHAIN=go1.25.0 go test ./internal/mcpserver
GOTOOLCHAIN=go1.25.0 go test ./internal/ai/providers/...
GOTOOLCHAIN=go1.25.0 go test ./internal/ui/...
```

- [ ] MCP smoke passes.
- [ ] AI provider tests pass.
- [ ] UI smoke passes.

## Compare After Window

After the shadow window has enough history:

```bash
test -f /var/lib/cf-sync/shadow/SHADOW_MODE_REPORT.md
test -f /var/lib/cf-sync/shadow/PYTHON_GO_PARITY_REPORT.md
tail -n 40 /var/lib/cf-sync/shadow/SHADOW_MODE_REPORT.md
tail -n 40 /var/lib/cf-sync/shadow/PYTHON_GO_PARITY_REPORT.md
```

- [ ] Agreement remains explainable.
- [ ] No unexpected drift class appears.
- [ ] No sensitive value is echoed in reports.

## Stop / Roll Back

```bash
sudo systemctl stop cf-shadow.service
sudo systemctl disable cf-shadow.service
sudo systemctl daemon-reload
```

- [ ] Go shadow is stopped.
- [ ] Python authority remains available.
- [ ] Shadow evidence remains intact unless explicitly archived elsewhere.

## Final Operator Note

GO SHADOW.
