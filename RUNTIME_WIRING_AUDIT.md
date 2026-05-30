# Runtime Wiring Audit

**Date:** 2026-05-30  
**Method:** Source code trace only. No assumptions. Every claim has a file:line citation.  
**Binary audited:** `cmd/crowdsec-sync` → `app.CrowdSecSyncApp`

---

## 1. recidive.RealService

### Constructor call path
```
cmd/crowdsec-sync/main.go → app.NewCrowdSecSyncApp(logger, cfg)
  internal/app/app.go:212:
    recidiv: recidive.NewService(recidive.Config{StateDir: cfg.StateDir})
```

### Dependency injection
```go
// internal/app/app.go:212
recidiv: recidive.NewService(recidive.Config{StateDir: cfg.StateDir})
```

Fields set at construction:
- `StateDir` = `cfg.StateDir` ✓
- `BanSource` = **nil** (not injected)
- `Escalator` = **nil** (not injected)

### Scheduler registration path
```
app.CrowdSecSyncApp.Run()
  → scheduler.IntervalRunner.Run(ctx, task)
    → task(runCtx):
        internal/app/app.go:303-304:
          if err := a.recidiv.Run(runCtx); ...
```

### Runtime execution path
```go
// internal/recidive/service.go:107
func (s *RealService) Run(ctx context.Context) error {
    if s.cfg.BanSource == nil {
        return nil  // ← IMMEDIATE RETURN
    }
    ...
```

**Execution result:** `return nil` on every call. No ban reading. No escalation.

### Proof
- `internal/app/app.go:212` — `recidive.Config{StateDir: cfg.StateDir}` — only StateDir set
- `internal/recidive/service.go:107` — `if s.cfg.BanSource == nil { return nil }`
- `internal/recidive/service.go:167` — `if duration != "" && s.cfg.Escalator != nil {` — Escalator also nil

### Classification: **DEAD_CODE**

The service is instantiated and called every cycle, but executes no logic because `BanSource` is nil. The 60s-cycle call succeeds silently with zero effect. No ban is ever read, no escalation is ever issued.

**Root cause:** `recidive.Config` requires a `RecentBanSource` implementation. Neither `crowdsec.Client.ListRecentBans` (which reads decisions.log) nor a cross-source adapter has been injected.

---

## 2. cidrban.RealService

### Constructor call path
```
cmd/crowdsec-sync/main.go → app.NewCrowdSecSyncApp(logger, cfg)
  internal/app/app.go:213-225:
    cidr: cidrban.NewService(cidrban.Config{
        StateDir:  cfg.StateDir,
        BanSource: &cidrBanSourceAdapter{src: csClient, shield: shield, csAllowlist: csClient, ...},
        CFBanner:  cfClient,
        CFRuleGetter: cfClient,
        CFDeleter: cfClient,
        CSRangeBanner: csClient,
        ZoneID: cfg.Cloudflare.ZoneID,
    })
```

### Dependency injection
All required dependencies injected:
- `BanSource` = `&cidrBanSourceAdapter{src: csClient, ...}` ✓
- `CFBanner` = `cfClient` (cloudflare.Client) ✓
- `CFRuleGetter` = `cfClient` ✓
- `CFDeleter` = `cfClient` ✓
- `CSRangeBanner` = `csClient` (crowdsec.Client) ✓
- `ZoneID` = `cfg.Cloudflare.ZoneID` ✓

### Scheduler registration path
```
app.CrowdSecSyncApp.Run()
  → task(runCtx):
      internal/app/app.go:298-301:
        if !a.shadowMode {
          if err := a.cidr.Run(runCtx); ...
        }
```

### Runtime execution path
```go
// internal/cidrban/service.go:123
func (s *RealService) Run(ctx context.Context) error {
    if s.cfg.BanSource == nil { return nil }
    bans, err := s.cfg.BanSource.ListRecentBans(ctx)  // calls cidrBanSourceAdapter
    // cidrBanSourceAdapter → csClient.ListRecentBans() → reads decisions.log
    // Groups by /24, threshold=2, adds CF + CS range decisions
```

### Constraints
- **Shadow mode:** suppressed by `if !a.shadowMode` guard (`internal/app/app.go:298`)
- **Live mode:** fully executable — reads CS decisions, writes to CF, issues cscli range decisions
- **Source data:** reads `decisions.log` via `csClient.ListRecentBans()` (7-day lookback)

### Classification: **ACTIVE** (live mode) / **PARTIALLY_ACTIVE** (shadow mode)

All dependencies injected. In live mode, the service runs every 60s cycle and can mutate CF.
In shadow mode, the scheduler guard prevents execution — correct by design.

---

## 3. modsecurity.RealService

### Constructor call path
```
cmd/crowdsec-sync/main.go → app.NewCrowdSecSyncApp(logger, cfg)
  internal/app/app.go:211:
    modsec: modsecurity.NewService(modsecurity.Config{NginxLogDir: cfg.CrowdSec.NginxLogDir})
```

### Dependency injection
Fields set at construction:
- `NginxLogDir` = `cfg.CrowdSec.NginxLogDir` (`/var/log/nginx`) ✓
- `CFBanner` = **nil** (not injected)
- `StateDir` = **""** (empty string, not injected)

### Scheduler registration path
```
app.CrowdSecSyncApp.Run()
  → task(runCtx):
      internal/app/app.go:305-307:
        if err := a.modsec.Run(runCtx); ...
```

No shadow-mode guard (unlike cidrban). Executes in both live and shadow mode.

### Runtime execution path
```go
// internal/modsecurity/service.go:96
func (s *RealService) Run(ctx context.Context) error {
    logPath := filepath.Join(s.cfg.NginxLogDir, "error.log")
    events, err := parseModSecEvents(logPath)  // reads nginx error.log
    if err != nil || len(events) == 0 {
        return nil  // ← returns nil if no events
    }
    ...
    if s.cfg.CFBanner != nil {
        // internal/modsecurity/service.go:133
        _, _ = s.cfg.CFBanner.AddIPAccessRule(ctx, "", ip, "modsec-ban", "ip")
    }
    // CFBanner is nil → this branch never executes
```

### Host evidence
```
nginx not compiled with modsec
0 ModSec lines in /var/log/nginx/error.log
```

ModSecurity is not installed. nginx error.log contains only Lua CrowdSec debug lines.
`parseModSecEvents()` searches for `"ModSecurity: Access denied"` pattern → 0 matches.

### Classification: **DEAD_CODE**

The service runs every cycle (no shadow guard), parses nginx error.log, finds 0 ModSec events, returns nil. Even if ModSec events existed, `CFBanner=nil` prevents any CF mutation.

**Root cause:** (1) `CFBanner` not injected, (2) ModSecurity not installed on host.

---

## 4. crowdsecevent.Service

### Constructor call path
```
cmd/crowdsec-sync/main.go → app.NewCrowdSecSyncApp(logger, cfg)
  → (inside Run()) internal/app/app.go:276:
      wafRuntime := newWAFReportingRuntime(ctx, logger, cfg, abuse, better)
        → internal/app/reporting_runtime.go:29-65:
            if abuse == nil { return nil }  // GATE: requires AbuseIPDB key
            service := reporting.New(abuse.Executor, telemetry, ...)
            crowdsecSource: crowdsecevent.NewLiveSource(cfg.CrowdSec.DecisionsLog, ...)
            crowdsecService: crowdsecevent.NewService(service)
```

### Dependency injection
- `abuse` from `NewCrowdSecSyncApp` — requires `cfg.AbuseIPDB.APIKey != ""` AND `reporting enabled`
- `crowdsecevent.LiveSource` reads `cfg.CrowdSec.DecisionsLog` (`/var/log/crowdsec/decisions.log`)
- `reporting.Service` has `abuse.Executor` (HTTP transport to AbuseIPDB)

**Production gate:** `if abuse == nil { return nil }` at `reporting_runtime.go:30` — if no ABUSEIPDB_KEY, the entire wafRuntime is nil and all three services (crowdsecevent, openrestyevent, outbox) are no-ops.

In `crowdsec-sync-live.env`: `ABUSEIPDB_KEY=...` and `ABUSEIPDB_REPORTING_ENABLED=true` → abuse client will be non-nil → **gate passes**.

### Scheduler registration path
```
app.CrowdSecSyncApp.Run() → task(runCtx):
  internal/app/app.go:311:
    wafRuntime.processCrowdSec(runCtx, l)
```

### Runtime execution path
```go
// internal/app/reporting_runtime.go:80
func (r *wafReportingRuntime) processCrowdSec(ctx, logger) {
    events, err := r.crowdsecSource.Read(ctx)  // reads decisions.log
    for _, event := range events {
        r.crowdsecService.Process(ctx, event)  // → AbuseIPDB report + telemetry
    }
}
```

`crowdsecevent.LiveSource.Read()` reads `decisions.log` (written by `crowdsec-poller`).
Filters: `origin∈{crowdsec, cscli}` — excludes CAPI decisions.

### Classification: **ACTIVE** (when ABUSEIPDB_KEY present)

Fully wired. Reads decisions.log, processes local-origin bans, reports to AbuseIPDB with dedup+outbox.

---

## 5. openrestyevent.Service

### Constructor call path
```
newWAFReportingRuntime()
  internal/app/reporting_runtime.go:47,61:
    openrestySource: openrestyevent.NewLiveSource(cfg.OpenResty.EventsFile)
    openrestyService: openrestyevent.NewService(service)
```

`cfg.OpenResty.EventsFile` = `/run/crowdsec-lua/events.jsonl` (from config default).

### Dependency injection
- `openrestySource` = `openrestyevent.LiveSource{EventsFile: "/run/crowdsec-lua/events.jsonl"}` ✓
- `openrestyService` = `openrestyevent.Service` with reporting service ✓
- Same AbuseIPDB gate as crowdsecevent

### Scheduler registration path
```
internal/app/app.go:312:
  wafRuntime.processOpenResty(runCtx, l)
```

### Runtime execution path
```go
// internal/adapters/openrestyevent/live.go:41
if err := os.Rename(s.EventsFile, procFile); err != nil {
    return []RawEvent{}, nil  // ← if file doesn't exist, returns empty
}
```

### Host evidence
```
ls /run/crowdsec-lua/:
  bans.json      (exists — 983 bytes)
  events.jsonl   (DOES NOT EXIST)
```

The Lua layer currently only writes `bans.json` (ban list for nginx enforcement).
`events.jsonl` is written only when Lua emits escalation events (honeypot hits, heuristic triggers).
No such events are currently being generated.

### Classification: **PARTIALLY_ACTIVE**

Code is correctly wired. The service runs every cycle. When `events.jsonl` does not exist, `os.Rename()` fails silently and the service returns an empty event list — no-op, no error. Will become active the moment Lua emits events to `events.jsonl`.

---

## 6. cloudflareevent.Service (WAF replay)

### Constructor call path
```
cmd/cf-sync/main.go:303:
  wafReplay := newWAFReplayService(cf, abuse, securityTelemetry, trustRegistry, cfg, reportingStores)
    internal/cmd/cf-sync/runtime_wiring.go:
      if abuse == nil { return nil }  // GATE
      reportingService := reporting.New(abuse.Executor, ...)
      stores.Configure(reportingService)
      return cloudflareevent.NewService(cf, reportingService)
```

**Critical:** this wiring is in `cmd/cf-sync`, NOT in `cmd/crowdsec-sync`.

### Dependency injection
In `cmd/cf-sync --mode daemon`:
- `cf` = Cloudflare client ✓
- `abuse` = AbuseIPDB client (non-nil when ABUSEIPDB_KEY set) ✓
- WAF replay reads CF GraphQL API for WAF events since last cursor
- Cursor persisted in SQLite (`sqlite.CursorStore`)

### Scheduler registration path
```
cmd/cf-sync/main.go:304:
  runDaemon(..., wafReplay, cursorStore)
    cmd/cf-sync/daemon_runtime.go:431:
      startWAFReplayPoller(childCtx, logger, interval, zoneID, wafReplay, cursorStore)
        → goroutine: loops every interval
```

### Runtime execution path
```go
// cmd/cf-sync/daemon_runtime.go:144
func runWAFReplayIteration(...) time.Time {
    report, err := wafReplay.ProcessSince(ctx, zoneID, querySince)
    // Fetches CF WAF events → classifies → reports to AbuseIPDB
    // Updates persistent cursor in SQLite
```

### Host evidence
- `cmd/cf-sync` is NOT currently managed by a systemd unit as live service
- `cf-shadow.service` uses `cmd/cf-shadow` (which internally uses `cmd/crowdsec-sync` path)
- WAF replay is **not running** in any current production service

### Classification: **PARTIALLY_ACTIVE**

Fully wired inside `cmd/cf-sync --mode daemon`. Not active because no systemd unit runs `cmd/cf-sync` in daemon mode on this host. Will become active when `crowdsec-sync-go.service` is augmented or `cf-sync` daemon is deployed.

---

## Summary

| Component | Instantiated | Wired | Reachable | Can Mutate | Production-Ready | Classification |
|---|---|---|---|---|---|---|
| recidive.RealService | ✅ | ❌ BanSource=nil | ✅ | ❌ (no-op) | ❌ | **DEAD_CODE** |
| cidrban.RealService | ✅ | ✅ all deps | ✅ | ✅ (live only) | ✅ | **ACTIVE** |
| modsecurity.RealService | ✅ | ❌ CFBanner=nil | ✅ | ❌ (no-op) | ❌ | **DEAD_CODE** |
| crowdsecevent.Service | ✅ | ✅ (abuse required) | ✅ | ✅ (AbuseIPDB) | ✅ | **ACTIVE** |
| openrestyevent.Service | ✅ | ✅ (events.jsonl) | ✅ | ⚠️ (no events) | ⚠️ | **PARTIALLY_ACTIVE** |
| cloudflareevent.Service | ✅ (cf-sync only) | ✅ | ❌ (not running) | ✅ (when running) | ❌ | **PARTIALLY_ACTIVE** |

### Action Items

1. **recidive.RealService**: wire `BanSource = crowdsecevent adapter` (decisions.log → recidive.Ban) and `Escalator = csClient`. Currently DEAD_CODE every cycle.

2. **modsecurity.RealService**: mark as **RETIRED**. ModSec not installed. Remove from scheduler to eliminate wasted file-open syscall per cycle.

3. **cloudflareevent.Service**: deploy `cmd/cf-sync --mode daemon` or port WAF replay into `cmd/crowdsec-sync` scheduler.

4. **openrestyevent.Service**: no action — will self-activate when Lua emits events.
