# Notifier Replacement Audit

**Date:** 2026-05-30  
**Question:** Can Go fully replace crowdsec-notifier.service?  
**Method:** Source code trace + production evidence. No assumptions.

---

## Decision Propagation Trace

```
CrowdSec agent detects attack
       │
       ▼ (nearly instant — same process, same SQLite DB)
CrowdSec decision created (scope=Ip, origin=crowdsec, type=ban)
       │
       ▼ (up to 60s — Go scheduler interval)
ListActiveBans() → cscli decisions list -o json (15s timeout)
  → FilterActiveBanIPs(): origin∈{crowdsec,cscli} AND scope=Ip AND type=ban
       │
       ▼ (same cycle — sequential)
buildSyncPlan():
  banSet = normalized(activeBans) - shield(protected) - allowlist(cs)
  cfSet  = ListIPAccessRulesByTag(zoneID, "crowdsec-local-ban")
  toAdd  = banSet - cfSet   [set arithmetic — natural dedup]
  toDelete = cfSet - banSet
       │
       ▼ (same cycle — if !shadowMode)
syncCloudflare():
  for ip in toAdd:
    AddIPAccessRule(ctx, zoneID, ip, "crowdsec-local-ban", "ip")
    sleep(100ms)
  for ip in toDelete:
    DeleteIPAccessRule(ctx, zoneID, ruleID)
    sleep(100ms)
       │
       ▼
Cloudflare edge enforcement active
```

**Source evidence:**  
- `internal/app/app.go:syncCloudflare()` — full loop  
- `internal/crowdsec/source/cscli.go:CSCLISource.ListAlerts()` — 15s timeout  
- `internal/app/app.go:buildSyncPlan()` — set arithmetic, no state carry-over  
- `internal/cloudflare/client.go:AddIPAccessRule()` — CF API call

---

## Maximum Propagation Delay

| Phase | Notifier | Go | Evidence |
|---|---|---|---|
| CS alert → decision | ~instant | ~instant | CrowdSec agent synchronous |
| Decision → CF push | 5s (group_wait) | **≤ 60s** (poll interval) | `notifications/cloudflare.yaml: group_wait: 5s` vs `cfg.Interval: 60s` |
| Total worst case | **~5s** | **~60s** | |

**Verdict:** Go introduces a maximum 60s CF enforcement gap per new decision.
iptables (crowdsec-firewall-bouncer) enforces immediately — CF is secondary layer.
60s gap is operationally acceptable for this threat profile.

---

## Missed-Decision Scenarios

### Scenario 1 — CAPI (Community Blocklist) decisions
- **Notifier:** filtered — `handle_abuseipdb()` requires `origin=crowdsec` (not CAPI)
- **Go:** filtered — `LOCAL_ORIGINS = {crowdsec, cscli}` (not CAPI)
- **Evidence:** `decisions.log` shows CAPI decisions with `origin=CAPI` — excluded by both
- **Verdict: NO CHANGE** — neither system handles CAPI. iptables bouncer does.

### Scenario 2 — Range-scope decisions (e.g., 192.175.111.0/24 from cscli)
- **Notifier:** NOT handled — `profiles.yaml default_range_remediation` has no notifier
- **Go ListActiveBans():** filtered — `scope.lower()=="ip"` excludes Range scope
- **Go cidrban:** handles /24 aggregation independently from recent bans (decisions.log)
- **Evidence:** `profiles.yaml`: `default_range_remediation` → no notifications block
- **Verdict: NO CHANGE** — both systems ignore Range-scope for the notifier path

### Scenario 3 — IPv6 decisions
- **Notifier:** handles IPv6 (pushes to CF via API)
- **Go:** handles IPv6 — `net.ParseIP(ip)` accepts IPv6; CF access rules support IPv6
- **Evidence:** live cscli: `2001:41d0:303:caf::1` scope=Ip → visible to `FilterActiveBanIPs()` ✓
- **Verdict: NO CHANGE**

### Scenario 4 — Decisions created during Go downtime
- Go reads CF API AND cscli at cycle start — both are persistent (CF API = canonical)
- On restart: `ListIPAccessRulesByTag()` reads current CF state; `ListActiveBans()` reads current cscli
- `toAdd = cscli_active - cf_rules` — will catch any gap from downtime
- **Verdict: SAFE** — catch-up within 1 cycle after restart

---

## Duplicate-Decision Scenarios

### Scenario 1 — Notifier ran first, then Go runs
- IP already in CF with `crowdsec-local-ban` tag
- Go's `cfSet = ListIPAccessRulesByTag(...)` → IP is in cfSet
- `toAdd = banSet - cfSet` → IP NOT in toAdd → **not added again**
- **Verdict: SAFE** — natural dedup via set arithmetic

### Scenario 2 — Go runs first, then notifier runs (if both active simultaneously)
- Go adds IP to CF → notifier also fires → CF receives duplicate create request
- CF API: `POST /zones/{id}/firewall/access_rules/rules` for existing IP
- CF API behavior: returns existing rule (idempotent) or creates duplicate
- **This is the TRANSITION RISK** during parallel operation
- **Mitigation:** stop notifier before Go takes authority (see CUTOVER_RUNBOOK.md Step 3)
- **Verdict: SAFE if sequenced correctly; RISKY if parallel**

---

## Restart Scenarios

| Scenario | Behavior | Safety |
|---|---|---|
| Normal restart | Reads CF API + cscli fresh; recomputes plan; catches up | ✅ SAFE |
| Restart with new decisions during downtime | `toAdd` includes decisions missed during gap | ✅ SAFE |
| Restart with CF rules that expired | `toDelete` includes expired decisions | ✅ SAFE |
| Restart while `AddIPAccessRule` was in-flight | CF API is canonical; rule either added or not; idempotent on next cycle | ✅ SAFE |
| Restart while `DeleteIPAccessRule` was in-flight | Rule either deleted or not; `toDelete` re-includes it on next cycle if CS ban also expired | ✅ SAFE |
| State file corruption (recidivists.json, cidr-banned.json) | Services re-initialize from empty state; restart tracking from scratch | ⚠️ LIMITATION (history lost, not data loss) |
| AbuseIPDB outbox on restart | SQLite-backed — survives restart | ✅ SAFE |

---

## Crash Scenarios

### Go crash during `AddIPAccessRule`
- CF API call may be in-flight or completed
- On restart: `ListIPAccessRulesByTag()` reads current CF state
- If added: IP in cfSet → not re-added (dedup)
- If not added: IP in toAdd → added next cycle
- **Verdict: SAFE — idempotent by design**

### Go crash during `DeleteIPAccessRule`
- Rule may or may not be deleted
- On restart: if rule still in CF AND CS ban expired → still in toDelete → deleted next cycle
- On restart: if rule was deleted → not in cfSet → already handled
- **Verdict: SAFE — idempotent by design**

### Go crash during `ListIPAccessRulesByTag`
- No mutation has occurred
- Full restart from clean state
- **Verdict: SAFE**

---

## Limitations vs Notifier

| Dimension | Notifier | Go | Impact |
|---|---|---|---|
| Propagation model | Event-driven (push) | Polling (60s) | Max 60s CF enforcement gap |
| CF enforcement gap | ~5s | ≤60s | Accepted — iptables is T+0 |
| AbuseIPDB reporting | Real-time (30s batch) | Polling (decisions.log, 60s cycle) | ≤30s additional delay |
| Range decisions → CF | Not handled | Not handled | No change |
| CAPI decisions | Not handled | Not handled | No change |
| Restart recovery | State file (notifier-state.json) | Stateless (CF API canonical) | Go is MORE robust |
| Crash recovery | May lose in-flight state | Idempotent next cycle | Go is MORE robust |
| Dedup | In-memory (120s CF dedup TTL) | Set arithmetic (CF API source of truth) | Go is MORE robust |
| AbuseIPDB dedup | In-memory (7d TTL, file-backed) | SQLite outbox (7d TTL, durable) | Go is MORE robust |

---

## Verdict

**SAFE_WITH_LIMITATIONS**

Go can fully replace `crowdsec-notifier.service` with the following understood limitations:

1. **Max 60s CF enforcement delay** vs notifier's ~5s. iptables (firewall bouncer) enforces at T+0 making this operationally irrelevant for the current threat profile.

2. **Parallel operation is risky** — must stop notifier before Go takes CF authority. Sequencing documented in CUTOVER_RUNBOOK.md.

3. **Range-scope decisions**: neither system handles them for CF push. CIDR aggregation handles /24 blocking via a separate path.

The Go implementation is MORE robust than the notifier in crash/restart scenarios due to stateless CF API reads and durable SQLite AbuseIPDB outbox.
