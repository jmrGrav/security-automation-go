# Production Cutover Runbook

**Date:** 2026-05-30  
**Scope:** Controlled authority — Go takes over CF enforcement + AbuseIPDB reporting  
**Recommendation: CONTROLLED AUTHORITY** (not full cutover — see Lua section)

---

## Service Map (current production)

| Service | Binary | Role | Status post-cutover |
|---|---|---|---|
| `crowdsec.service` | CrowdSec agent | Threat detection, decision engine | **KEEP** |
| `crowdsec-firewall-bouncer.service` | CrowdSec bouncer | iptables/nftables enforcement | **KEEP** |
| `crowdsec-notifier.service` | `crowdsec-notifier.py` (port 9999) | Real-time CF push + AbuseIPDB | **STOP** (Go replaces) |
| `crowdsec-cf-sync.service` | `crowdsec-cf-sync` (Python) | Lua push + ModSec + recidive + reconcile | **KEEP in reduced mode** |
| `crowdsec-poller.service` | `crowdsec-poller.py` | decisions.log writer (Vector/BetterStack) | **KEEP** |
| `cf-shadow.service` | Go | Shadow validator (read-only) | **STOP** (becomes live) |

---

## What Go Replaces (controlled authority)

| Python capability | Go replacement | Evidence |
|---|---|---|
| CF push (real-time via notifier) | `syncCloudflare()` — 60s poll | `app.CrowdSecSyncApp.syncCloudflare()` |
| CF reconcile/expiry | Same `syncCloudflare()` — to_delete path | `buildSyncPlan()` |
| CIDR /24 auto-ban | `cidrban.RealService.Run()` | wired in scheduler loop |
| AbuseIPDB (crowdsec events) | `crowdsecevent.Service` + outbox | `reporting_runtime.processCrowdSec()` |
| AbuseIPDB (openresty) | `openrestyevent.Service` | `reporting_runtime.processOpenResty()` |
| AbuseIPDB (WAF replay) | `cloudflareevent.Service` | `startWAFReplayPoller()` in `cmd/cf-sync` |
| BetterStack security events | `telemetry/sinks.BetterStackSink` | `newSecurityTelemetry()` |

## What Python KEEPS (reduced mode)

| Python capability | Why Go doesn't replace yet |
|---|---|
| Lua bans.json push | `push_lua_state()` not ported to Go — nginx enforcement depends on it |
| ModSec → CF ban | `modsecurity.RealService` CFBanner=nil — parses logs but doesn't ban |
| Recidive escalation | `recidive.RealService` BanSource=nil — no-op |
| BetterStack operational events | `send_to_betterstack()` for cf-sync operational data |

**crowdsec-cf-sync continues running in reduced mode:** with `CF_NOTIFIER_ACTIVE=1` already set,
it skips the main CF push (Go handles it). It keeps doing: Lua push, ModSec, recidive, BetterStack.

---

## Capability Map After Controlled Authority

| Capability | Before | After | Delta |
|---|---|---|---|
| CF edge (new bans) | Notifier real-time | Go 60s poll | Max 60s latency increase |
| CF edge (cleanup) | Python reconcile | Go syncCloudflare() to_delete | Equivalent |
| CrowdSec decisions | Agent independent | Agent independent | No change |
| OpenResty/Lua bans.json | Python push | **Python push continues** | No change |
| AppSec → CF | Notifier (profile route) | Go ListActiveBans() 60s | Max 60s latency |
| AbuseIPDB (crowdsec) | Notifier | Go crowdsecevent | Equivalent + outbox retry |
| AbuseIPDB (openresty) | Not in Python main | Go openrestyevent | Enhancement |
| AbuseIPDB (WAF replay) | Python WAF poll | Go WAF replay + cursor | Enhancement |
| ModSecurity CF ban | Python cf-sync | Python cf-sync (unchanged) | No change |
| Recidive | Python cf-sync | Python cf-sync (unchanged) | No change |
| CIDR /24 | Python cf-sync | Go cidrban.RealService | Equivalent |
| BetterStack security | Python send_to_betterstack | Go BetterStack sink | Equivalent |
| BetterStack operational | Python send_to_betterstack | Python cf-sync (unchanged) | No change |
| iptables enforcement | crowdsec-firewall-bouncer | crowdsec-firewall-bouncer | No change |

---

## Pre-Cutover Checklist

Run all checks on the production host before starting.

### 1. Shadow criterion verified

```bash
cat /var/lib/security-automation-go/shadow/SHADOW_MODE_REPORT.md | grep "7-day agreement\|Status\|in_sync"
# Expected: 7-day agreement ≥99.9% OR "PENDING" with ≥6 days data and current avg ≥99.9%
```

**Block if:** agreement below 99.9% OR protected-IP drift > 0.

### 2. Go binary is current

```bash
cd /home/jm/Documents/security-automation-go
git log --oneline -3
go build ./cmd/cf-sync/ ./cmd/crowdsec-sync/ 2>&1 && echo BUILD OK
go test ./... 2>&1 | grep FAIL && echo FAIL || echo ALL PASS
```

### 3. Credentials confirmed

```bash
# Go config will use these — verify they match Python's working config
sudo grep "CF_API_TOKEN\|CF_ZONE_ID\|ABUSEIPDB_KEY\|BETTERSTACK" /etc/crowdsec/cf-sync.env
# Cross-check with Go config
sudo cat /etc/security-automation-go/cf-shadow.yaml
```

### 4. Anti-self-ban shield covers all management IPs

```bash
# List server's own IPs
ip -j addr | python3 -c "import json,sys; [print(ai['local']) for iface in json.load(sys.stdin) for ai in iface.get('addr_info',[])]"
# Verify the Go shield includes them (it auto-detects via 'ip -j addr')
# Also verify no management CIDRs that need manual addition to NewWithExtraRanges()
```

**Block if:** any management IP, VPN range, or bastion is not in protected ranges.

### 5. CrowdSec allowlist is current

```bash
sudo cscli allowlists inspect my_allowlist 2>/dev/null | head -20
# Go's ListAllowlist() will fetch this each cycle. Verify it contains expected entries.
```

### 6. Python notifier is confirmed live

```bash
systemctl is-active crowdsec-notifier.service
ss -tlnp | grep 9999
# Must show python3 listening. Stopping it is the critical step.
```

### 7. CF current rule count

```bash
# Check how many rules exist now (after shadow mode — Go didn't mutate)
curl -s -X GET "https://api.cloudflare.com/client/v4/zones/<YOUR_ZONE_ID>/firewall/access_rules/rules?per_page=1" \
  -H "Authorization: Bearer <YOUR_CLOUDFLARE_TOKEN>" | python3 -c "import json,sys; d=json.load(sys.stdin); print('CF rules:', d['result_info']['total_count'])"
```

### 8. decisions.log is being updated

```bash
tail -3 /var/log/crowdsec/decisions.log
# Must show recent entries. Go's ListRecentBans() and crowdsecevent read this file.
```

---

## Go Live Mode Configuration

### Create `/etc/security-automation-go/crowdsec-sync-live.env`

```bash
sudo tee /etc/security-automation-go/crowdsec-sync-live.env > /dev/null << 'EOF'
CF_API_TOKEN=<YOUR_CLOUDFLARE_TOKEN>
CF_ZONE_ID=<YOUR_ZONE_ID>
ABUSEIPDB_KEY=<YOUR_ABUSEIPDB_KEY>
ABUSEIPDB_REPORTING_ENABLED=true
BETTERSTACK_SOURCE_TOKEN=<YOUR_BETTERSTACK_TOKEN>
STATE_DIR=/var/lib/security-automation-go
DECISIONS_LOG=/var/log/crowdsec/decisions.log
NGINX_LOG_DIR=/var/log/nginx
EOF
sudo chmod 600 /etc/security-automation-go/crowdsec-sync-live.env
```

### Create `/etc/security-automation-go/crowdsec-sync-live.yaml`

```bash
sudo tee /etc/security-automation-go/crowdsec-sync-live.yaml > /dev/null << 'EOF'
version: v1
global:
  service_name: crowdsec-sync
  log:
    level: info
    format: json
cloudflare:
  zone_id: <YOUR_ZONE_ID>
crowdsec:
  decisions_log: /var/log/crowdsec/decisions.log
  nginx_log_dir: /var/log/nginx
  bin_path: cscli
  timeout: 15s
  allowlist_name: my_allowlist
interval: 60s
state_dir: /var/lib/security-automation-go
EOF
```

### Build live binary

```bash
cd /home/jm/Documents/security-automation-go
go build -o bin/crowdsec-sync ./cmd/crowdsec-sync/
sudo cp bin/crowdsec-sync /opt/security-automation-go/bin/crowdsec-sync
```

### Install `/etc/systemd/system/cf-sync.service`

Copy the deployed template from `deployments/systemd/cf-sync.service` and populate the `EnvironmentFile`:

```bash
sudo cp /home/jm/Documents/security-automation-go/deployments/systemd/cf-sync.service \
    /etc/systemd/system/cf-sync.service
sudo systemctl daemon-reload
```

The deployed unit (`deployments/systemd/cf-sync.service`) contains:

```ini
[Unit]
Description=Cloudflare to CrowdSec Reconciliation Daemon
After=network.target crowdsec.service

[Service]
Type=simple
DynamicUser=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
DeviceAllow=/dev/null rw
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
StateDirectory=security-automation-go
RuntimeDirectory=security-automation-go
LogsDirectory=security-automation
LogsDirectoryMode=0750
WorkingDirectory=/var/lib/security-automation-go
EnvironmentFile=-/etc/security-automation-go/security-automation.env
Environment=STATE_DIR=/var/lib/security-automation-go
ExecStart=/usr/local/bin/cf-sync -mode daemon -interval 1m
Restart=always
RestartSec=30
StartLimitIntervalSec=300
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
```

---

## Cutover Sequence

Execute each step only after verifying the previous one.

### Step 1 — Start Go in live mode (parallel with Python)

```bash
sudo systemctl start cf-sync.service
sleep 5
sudo systemctl is-active cf-sync.service
sudo journalctl -u cf-sync -n 20 --no-pager
```

**Expected output:**
```
"msg":"starting crowdsec sync daemon"
"msg":"cf sync plan","shadow_mode":false,"active_bans":N,"cf_rules":N,"to_add":0,"to_delete":0
"msg":"cf sync complete"  (or no mutation line = already in sync)
```

**Block if:**
- Service fails to start
- `to_add > 0` on first cycle (unexpected additions)
- Any error from ListActiveBans or ListIPAccessRulesByTag
- `shadow_mode: true` (misconfiguration)

### Step 2 — Verify 3 consecutive cycles

```bash
# Wait 3 minutes
sleep 180
sudo journalctl -u cf-sync --since "$(date -d '4 minutes ago' '+%Y-%m-%d %H:%M:%S')" --no-pager \
  | grep "cf sync plan\|cf sync complete\|WARN\|ERROR"
```

**Expected:** 3 cycles with `to_add=0, to_delete=0`. No WARN or ERROR.

**Block if:** any unexpected CF mutation or error.

### Step 3 — Stop crowdsec-notifier (hand-off CF push to Go)

This is the critical step. Go and the notifier would otherwise double-manage CF rules.

```bash
# Record current CF rule count
RULES_BEFORE=$(curl -s "https://api.cloudflare.com/client/v4/zones/<YOUR_ZONE_ID>/firewall/access_rules/rules?per_page=1" \
  -H "Authorization: Bearer <YOUR_CLOUDFLARE_TOKEN>" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['result_info']['total_count'])")
echo "CF rules before notifier stop: $RULES_BEFORE"

# Stop the notifier
sudo systemctl stop crowdsec-notifier.service
sudo systemctl disable crowdsec-notifier.service

# Verify it's down
sudo systemctl is-active crowdsec-notifier.service
# Expected: inactive
ss -tlnp | grep 9999
# Expected: nothing
```

**Rollback if:** notifier stop fails or port 9999 still active after 10s.

### Step 4 — Verify Go handles first cycle without notifier

```bash
sleep 70
sudo journalctl -u cf-sync --since "$(date -d '2 minutes ago' '+%Y-%m-%d %H:%M:%S')" --no-pager \
  | grep "cf sync\|WARN\|ERROR"

# Verify CF rule count unchanged
RULES_AFTER=$(curl -s "https://api.cloudflare.com/client/v4/zones/<YOUR_ZONE_ID>/firewall/access_rules/rules?per_page=1" \
  -H "Authorization: Bearer <YOUR_CLOUDFLARE_TOKEN>" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['result_info']['total_count'])")
echo "CF rules after notifier stop: $RULES_AFTER"
echo "Delta: $((RULES_AFTER - RULES_BEFORE)) rules"
```

**Expected:** delta = 0 or ≤ 1 (a ban that expired naturally).
**Block if:** delta > 2 (unexpected rule changes).

### Step 5 — Enable Go service at boot

```bash
sudo systemctl enable cf-sync.service
# Stop shadow mode (no longer needed — Go is live)
sudo systemctl stop cf-shadow.service
sudo systemctl disable cf-shadow.service
echo "Go live mode active. Shadow mode stopped."
```

### Step 6 — Keep Python cf-sync running (reduced mode)

```bash
# crowdsec-cf-sync continues — it still does:
# - Lua bans.json push (critical for OpenResty)
# - ModSec log scanner → CF ban (modsec-ban tag)
# - Recidive escalation
# - BetterStack operational events
# CF_NOTIFIER_ACTIVE=1 is already set — cf-sync skips the main CF push
sudo systemctl is-active crowdsec-cf-sync.service
# Expected: active
```

**Do NOT stop crowdsec-cf-sync at this stage.**

---

## Success Criteria

Check after 30 minutes of live operation:

```bash
# 1. Go is running cleanly
sudo systemctl is-active cf-sync.service

# 2. No unexpected CF mutations
sudo journalctl -u cf-sync --since "30 minutes ago" --no-pager \
  | grep "cf: added\|cf: removed" | wc -l
# Normal: small number proportional to actual CS decisions

# 3. AbuseIPDB outbox is processing
sudo ls -la /var/lib/security-automation-go/*.db 2>/dev/null
sudo journalctl -u cf-sync --since "30 minutes ago" --no-pager \
  | grep "abuseipdb\|reporting"

# 4. Python cf-sync still pushing Lua
sudo journalctl -u crowdsec-cf-sync --since "5 minutes ago" --no-pager \
  | grep "lua_sync\|Lua"

# 5. notifier is down and port 9999 is closed
sudo ss -tlnp | grep 9999
# Expected: empty

# 6. CF rule count is stable
# Run the rule count command from Step 3 and compare to RULES_BEFORE
```

---

## Failure Criteria (triggers rollback)

| Event | Threshold | Action |
|---|---|---|
| Go service crash | Any crash | Immediate rollback |
| Unexpected CF rule additions | > 5 rules in first 10 min | Investigate, rollback if unexplained |
| Protected IP in CF ban | Any occurrence | Immediate rollback + P0 investigation |
| CF API errors > 3 consecutive | 3 | Rollback, check token validity |
| CrowdSec decision count drops | > 50% drop | Check CrowdSec agent, not Go's fault |
| AbuseIPDB 429 rate limit | Sustained (> 10 min) | Reduce reporting, not rollback-worthy |

---

## Rollback Procedure

Execute in order. Takes < 2 minutes.

```bash
# Step R1 — Stop Go live service
sudo systemctl stop cf-sync.service

# Step R2 — Re-enable and start the notifier
sudo systemctl enable crowdsec-notifier.service
sudo systemctl start crowdsec-notifier.service
sleep 3
ss -tlnp | grep 9999
# Expected: python3 listening on 9999

# Step R3 — Verify Python notifier accepts connections
curl -s -X POST http://127.0.0.1:9999/crowdsec/event \
  -H "Content-Type: application/json" -d '[]' && echo "notifier OK"

# Step R4 — Re-enable shadow mode for evidence collection
sudo systemctl start cf-shadow.service

# Step R5 — Verify Python cf-sync is still running
sudo systemctl is-active crowdsec-cf-sync.service

# Step R6 — Document what happened
echo "Rollback completed at $(date)" | sudo tee -a /var/log/crowdsec/cutover.log
```

**Rollback validation:** After 2 cycles (2 minutes), Python logs should show:
```
CF Sync: notifier actif -- push deleguee (N IPs ignorees)
```

---

## Lua/OpenResty Strategy

**Current situation:** Python's `push_lua_state()` runs every 60s and writes `/run/crowdsec-lua/bans.json`. OpenResty reads this file for per-request nginx-level enforcement.

**During controlled authority:** crowdsec-cf-sync continues running → Lua push continues → nginx enforcement unaffected.

**For full cutover (future):** Port `push_lua_state()` to Go before stopping crowdsec-cf-sync. Until then, stopping crowdsec-cf-sync degrades nginx enforcement:
- bans.json freezes at last write
- New CrowdSec bans are enforced at CF edge but not at nginx level
- The Lua deadman timer (`LUA_STALE_SECS=120`, `LUA_HEAL_COOLDOWN_SECS=3600`) may trigger OpenResty reload
- `crowdsec-firewall-bouncer` (iptables) continues as fallback layer

**Mitigation if cf-sync must stop before Lua is ported:** Configure OpenResty to use `crowdsec-firewall-bouncer` as the enforcement source and disable the Lua file-poll mechanism.

---

## Notifier Stop Sequence (Detail)

The notifier is event-driven: CrowdSec sends alerts via HTTP to port 9999.
After stopping, in-flight and queued alerts are dropped. This is acceptable because:

1. Go's `syncCloudflare()` will pick up the decision from cscli on the next 60s poll.
2. Maximum enforcement gap = Go's next cycle start (≤ 60s from the alert being dropped).
3. The CrowdSec agent's iptables bouncer enforces immediately at system level — CF edge is secondary.

```
Timeline:
  T+0s    CrowdSec detects attack, creates decision
  T+0s    iptables bouncer enforces (immediate)
  T+0-5s  OLD: notifier pushes to CF (real-time) → NEW: notifier stopped
  T+0-60s NEW: Go polls cscli, detects new decision → pushes to CF
  T+60s   CF enforcement also active
```

The 60s CF enforcement gap is acceptable. iptables blocking continues throughout.

---

## Final Recommendation

### **CONTROLLED AUTHORITY** — ready to execute when shadow criterion is met

**Verdict rationale:**
- Shadow evidence: 99.92% agreement over 1,258 cycles; 0 false positives; 1 timing FN
- All P0/HIGH gaps resolved: anti-self-ban ✅, allowlist filter ✅, CIDR wiring ✅
- Go replaces the two critical Python services (notifier + cf-sync CF enforcement)
- Python cf-sync continues in reduced mode (Lua push) — zero regression on nginx enforcement

**Not FULL CUTOVER** because:
- Lua state push not ported → stopping cf-sync degrades nginx enforcement
- Recidive escalation not wired (BanSource nil) → cf-sync still needed for this
- ModSec CF bans (modsec-ban tag) not wired in Go → cf-sync still needed

**Not SHADOW CONTINUE** because:
- The shadow criterion is being met (99.92% > 99.9%)
- The remaining gaps are documented and their impact is quantified
- Evidence is sufficient to grant controlled authority

**Execute cutover on day 7 of shadow mode** (2026-06-05 or later) if the 7-day agreement holds.
Blocking condition: any protected-IP drift or agreement drop below 99.9% in the final 7-day window.

---

## Post-Cutover Monitoring

```bash
# Watch Go logs
journalctl -u cf-sync -f

# Watch Python reduced mode
journalctl -u crowdsec-cf-sync -f | grep -v "CF Sync\|notifier actif"

# CF rule count every 5 minutes
watch -n 300 'curl -s "https://api.cloudflare.com/client/v4/zones/<YOUR_ZONE_ID>/firewall/access_rules/rules?per_page=1" -H "Authorization: Bearer <YOUR_CLOUDFLARE_TOKEN>" | python3 -c "import json,sys; print(json.load(sys.stdin)[\"result_info\"][\"total_count\"], \"CF rules\")"'
```
# Go-Live Checklist

Mandatory gate before transferring **any** production authority from Python to Go.
Each item needs concrete, reproducible evidence (a command that passes / a test
that exercises the path). An item with no backing test is a **NO-GO** contributor.

Status legend: ✅ done · ⚠️ partial · ❌ blocking · n/a.

## A. Build & static checks
- [x] `go build ./...` — ✅ (2026-05-29)
- [x] `go vet ./...` — ✅
- [x] `gofmt -l .` clean — ✅
- [x] `go test ./...` 0 failures — ✅ (but 92/148 pkgs have no tests)
- [x] `go test -race ./...` clean — ✅ (bounded by coverage)

## B. Repository hygiene
- [x] Git initialised, private remote `security-automation-go`
- [x] CI runs build/vet/gofmt/test/race on push & PR
- [x] LICENSE, SECURITY.md, CONTRIBUTING.md, CODEOWNERS, .gitignore present
- [x] No secrets committed (`*.env.example` only, empty values)
- [x] README reflects real state (not Phase-0 scaffolding)

## C. Correctness of external-effect boundaries (BLOCKING)
- [ ] ❌ `internal/cloudflare/transport` has tests (POST/DELETE/GraphQL, retries, errors)
- [ ] ❌ `internal/crowdsec/adapter` (cscli) has tests (arg building, parsing, failures)
- [ ] ⚠️ `internal/cloudflare/mutate` coverage beyond 1 test file (complex mutators, list-item, ListID extraction TODO resolved)
- [ ] ❌ Rollback `planner.go:82` "PREVIOUS state" TODO resolved + tested

## D. Runtime safety validations (BLOCKING — named requirements)
- [ ] ❌ **Replay validation** — deterministic replay equivalence test exercising `internal/runtime/replay` (consistency pkg tested; replay pkg has 0 tests)
- [x]/⚠️ **Recovery validation** — `internal/runtime/recovery` has tests; confirm checkpoint-aware recovery end-to-end
- [ ] ❌ **Rollback validation** — governed rollback restores prior state on a live drill
- [ ] ❌ **Lost-lease validation** — `internal/runtime/ha` lease loss → fencing rejection (0 tests today)
- [ ] ❌ **Strict-HA validation** — strict HA startup refuses to run without valid lease
- [ ] ❌ **Journal/invariants** — `internal/runtime/journal` & `invariants` have tests

## E. Integration validations
- [ ] ❌ **AbuseIPDB validation** — report path verified against sandbox/dry-run, dedup keys preserved
- [ ] ❌ **Cloudflare validation** — access-rule add/remove + list-item + cleanup (keep `easycron`) verified against a test zone or recorded fixtures
- [ ] ⚠️ **WAF GraphQL discovery** — `client.go:87` TODO resolved

## F. Functional parity (from TEST_GAP_REPORT §3) (BLOCKING)
- [ ] ❌ Recidivist escalation ported (or descoped with sign-off)
- [ ] ❌ `/24` auto-ban ported (or descoped with sign-off)
- [ ] ❌ ModSecurity-log-based ban ported / decision recorded vs WAF-replay
- [ ] ❌ Allowlist additive sync wired in `cf-sync` (exclusion `immuniweb`)
- [ ] ⚠️ Cleanup flow wired in `cf-sync` (delete primitives exist)
- [ ] ⚠️ State migration: SQLite vs Python JSON documented (migrate or clean-start)

## G. Operational readiness
- [ ] Prometheus metrics scraped; dashboards for mutation counts by origin
- [ ] Alerts: mutation-while-dry-run, parity divergence, lease lost, rollback executed
- [ ] Systemd units: separate names/state from Python; restart + env secrets verified
- [ ] Rollback drill executed (stop Go → start Python) within RTO < 5 min
- [ ] Legacy stub cmds (`crowdsec-sync`, `cf-allowlist-sync`, `cf-cleanup`) removed or guarded

## H. Sign-off
- [ ] Dry-run parity ≥ threshold for ≥7 days (DEPLOYMENT_PLAN Phase 1)
- [ ] GO/NO-GO decision recorded in [docs/archive/DECISIONS.md](../archive/DECISIONS.md) with evidence links
- [ ] Named approver + date

---

### Current aggregate verdict (2026-05-29): **NO-GO for authority transfer.**
Sections A & B pass. Sections C–F have blocking items (untested mutation/cscli
boundaries; replay/lost-lease/strict-HA unvalidated; unported Python features).
**GO** only for: private repo + CI + **observe-only / dry-run** deployment with
Python authoritative and Go mutations disabled.
