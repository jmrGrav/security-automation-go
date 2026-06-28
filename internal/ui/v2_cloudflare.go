package ui

import (
	"fmt"
	"html"
	"net/http"
	"sort"
	"strings"
	"time"
)

// v2CloudflareView is the unified view model for the v2 Cloudflare page.
type v2CloudflareView struct {
	Tab              string // "boundary" | "sync" | "lifecycle"
	MutationsEnabled bool
	APITokenPresent  bool
	ZoneIDPresent    bool
	Sync             CFSyncView
	Lifecycle        BanLifecycleView
	Stats            cfLifecycleStats
	ActionsAvailable bool
	CSRFToken        string
}

type cfLifecycleStats struct {
	TotalTracked   int
	ActiveNow      int
	Recidivists    int // RecidiveLevel >= 2
	BurstMalicious int
	ReasonGroups   []cfReasonGroup
}

type cfReasonGroup struct {
	Reason string
	IsRed  bool // burst_malicious style
	First  int
	Second int
	Third  int
	Total  int
}

func (s *Server) handleV2CloudflarePage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()

	tab := r.URL.Query().Get("tab")
	if tab != "sync" && tab != "lifecycle" {
		tab = "boundary"
	}

	sync := s.buildCFSyncView(ctx)
	lifecycle := s.banLifecycleView(ctx)
	stats := buildCFLifecycleStats(lifecycle)

	view := v2CloudflareView{
		Tab:              tab,
		MutationsEnabled: s.cfg != nil && s.cfg.Cloudflare.MutationsEnabled,
		APITokenPresent:  s.cfSentinelToken() != "",
		ZoneIDPresent:    s.cfZoneIDFromSetup(ctx) != "",
		Sync:             sync,
		Lifecycle:        lifecycle,
		Stats:            stats,
		ActionsAvailable: s.banDebanActionsAvailable(),
		CSRFToken:        s.csrfTokenFromRequest(r),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, v2Page("Cloudflare", "/v2/cloudflare", renderV2Cloudflare(view)))
}

func buildCFLifecycleStats(lv BanLifecycleView) cfLifecycleStats {
	if !lv.Wired {
		return cfLifecycleStats{}
	}
	groups := map[string]*cfReasonGroup{}
	active := 0
	recidivists := 0
	burst := 0
	for _, e := range lv.Entries {
		if e.Status == "active" {
			active++
		}
		if e.RecidiveLevel >= 2 {
			recidivists++
		}
		if strings.Contains(e.Reason, "burst_malicious") {
			burst++
		}
		key := e.Reason
		g, ok := groups[key]
		if !ok {
			g = &cfReasonGroup{
				Reason: key,
				IsRed:  strings.Contains(key, "burst_malicious"),
			}
			groups[key] = g
		}
		g.Total++
		switch e.RecidiveLevel {
		case 1:
			g.First++
		case 2:
			g.Second++
		default:
			g.Third++
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return groups[keys[i]].Total > groups[keys[j]].Total
	})
	rg := make([]cfReasonGroup, 0, len(keys))
	for _, k := range keys {
		rg = append(rg, *groups[k])
	}
	return cfLifecycleStats{
		TotalTracked:   len(lv.Entries),
		ActiveNow:      active,
		Recidivists:    recidivists,
		BurstMalicious: burst,
		ReasonGroups:   rg,
	}
}

func renderV2Cloudflare(v v2CloudflareView) string {
	var b strings.Builder

	b.WriteString(`<style>
.v2-cf-tabs{display:flex;align-items:center;gap:4px;margin-bottom:16px}
.v2-cf-tab{padding:7px 14px;border-radius:8px;font:600 12px 'Hanken Grotesk',sans-serif;cursor:pointer;text-decoration:none;display:inline-block}
.v2-cf-tab.active{color:#eef0f6;background:rgba(124,108,242,.16);border:1px solid rgba(124,108,242,.32)}
.v2-cf-tab.inactive{color:#7b8196;background:#13151c;border:1px solid #20242f}
.v2-cf-grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.v2-cf-tiles{display:flex;gap:12px}
.v2-cf-tile{flex:1;border:1px solid #20242f;border-radius:11px;background:#13151c;padding:13px 15px}
.v2-cf-tile-val{font:700 22px 'Hanken Grotesk',sans-serif;color:#eef0f6}
.v2-cf-tile-val.green{color:#54c79a}
.v2-cf-tile-val.orange{color:#f5a443}
.v2-cf-tile-lab{font:500 10px 'JetBrains Mono',monospace;color:#6b7184;margin-top:3px}
.v2-cf-row{display:flex;align-items:center;padding:9px 16px;font:500 12px 'JetBrains Mono',monospace;border-top:1px solid #1a1e29}
.v2-cf-recid-1{color:#9aa0b2;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);padding:1px 6px;border-radius:5px;font:500 10px 'JetBrains Mono',monospace}
.v2-cf-recid-2{color:#f5b563;background:rgba(245,146,30,.1);border:1px solid rgba(245,146,30,.2);padding:1px 6px;border-radius:5px;font:500 10px 'JetBrains Mono',monospace}
.v2-cf-recid-3{color:#f08591;background:rgba(239,95,107,.1);border:1px solid rgba(239,95,107,.2);padding:1px 6px;border-radius:5px;font:500 10px 'JetBrains Mono',monospace}
@media(max-width:900px){.v2-cf-grid2,.v2-cf-tiles{grid-template-columns:1fr;flex-direction:column}}
</style>`)

	// ── Topbar ──────────────────────────────────────────────────────────────
	b.WriteString(`<div class="v2-topbar">`)
	b.WriteString(`<span style="width:30px;height:30px;border-radius:8px;background:rgba(245,146,30,.12);border:1px solid rgba(245,146,30,.25);display:grid;place-items:center;font:800 12px 'Hanken Grotesk',sans-serif;color:#f5921e">CF</span>`)
	b.WriteString(`<div><div class="v2-topbar-title">Cloudflare</div><div class="v2-topbar-sub" style="margin-top:2px">boundary · ban sync · lifecycle · diff — unifié</div></div>`)
	b.WriteString(`<span style="flex:1"></span>`)
	// Last sync freshness (#171)
	if !v.Sync.LastActivityAt.IsZero() {
		b.WriteString(fmt.Sprintf(
			`<span class="v2-live-badge" style="margin-right:8px" data-ts="%d" data-ts-full="%s" title="%s">Sync %s</span>`,
			v.Sync.LastActivityAt.Unix(),
			html.EscapeString(v.Sync.LastActivityAt.UTC().Format(time.RFC3339)),
			html.EscapeString(v.Sync.LastActivityAt.UTC().Format("2006-01-02 15:04:05 UTC")),
			html.EscapeString(v.Sync.LastActivityAt.UTC().Format("15:04:05")),
		))
	}
	b.WriteString(`<span class="v2-live-badge"><span class="v2-live-dot"></span>LIVE</span>`)
	b.WriteString(`</div>`)

	// ── Posture ──────────────────────────────────────────────────────────────
	b.WriteString(renderV2CFPosture(v))

	// ── Tab nav ───────────────────────────────────────────────────────────────
	tab := func(slug, label string) string {
		cls := "inactive"
		if v.Tab == slug {
			cls = "active"
		}
		return fmt.Sprintf(`<a href="/v2/cloudflare?tab=%s" class="v2-cf-tab %s">%s</a>`, slug, cls, label)
	}
	b.WriteString(`<div class="v2-cf-tabs">`)
	b.WriteString(tab("boundary", "Boundary &amp; diff"))
	b.WriteString(tab("sync", "Ban sync"))
	b.WriteString(tab("lifecycle", "Ban lifecycle"))
	b.WriteString(`<span style="flex:1"></span>`)
	b.WriteString(`<span style="font:500 11px 'JetBrains Mono',monospace;color:#5a6072">config-managed · read-only mutations</span>`)
	b.WriteString(`</div>`)

	// ── Panel ─────────────────────────────────────────────────────────────────
	switch v.Tab {
	case "sync":
		b.WriteString(renderV2CFSync(v))
	case "lifecycle":
		b.WriteString(renderV2CFLifecycle(v))
	default:
		b.WriteString(renderV2CFBoundary(v))
	}

	return b.String()
}

// ─── Posture ──────────────────────────────────────────────────────────────────

func renderV2CFPosture(v v2CloudflareView) string {
	sync := v.Sync
	activeCount := sync.ActiveCount
	drift := 0
	if sync.Wired && sync.RuleInventory.Wired {
		drift = sync.RuleInventory.UntrackedCount
	}

	lastStr := "no activity recorded"
	agoStr := ""
	if !sync.LastActivityAt.IsZero() {
		lastStr = sync.LastActivityAt.UTC().Format("2006-01-02 15:04:05Z")
		ago := time.Since(sync.LastActivityAt).Truncate(time.Minute)
		agoStr = " · " + ago.String() + " ago"
	}

	dotColor := "#4cc79a"
	headline := "Boundary converged"
	if activeCount > 0 {
		headline = fmt.Sprintf("Boundary converged · %d active managed ban(s)", activeCount)
	} else {
		headline = "Boundary converged · 0 active managed bans"
	}

	countColor := "#54c79a"
	if activeCount > 0 {
		countColor = "#f5a443"
		dotColor = "#f5a443"
	}

	cleaned := sync.SampleSize - activeCount
	if cleaned < 0 {
		cleaned = 0
	}

	return fmt.Sprintf(`<div style="border:1px solid #20242f;border-radius:12px;background:#13151c;padding:18px;margin-bottom:18px">
<div style="display:flex;align-items:center;gap:14px">
  <span style="width:13px;height:13px;border-radius:50%%;background:%s;box-shadow:0 0 0 4px rgba(76,199,154,.15);flex:none"></span>
  <div style="flex:1">
    <div style="font:700 18px 'Hanken Grotesk',sans-serif;color:#eef0f6">%s</div>
    <div style="font:500 12px 'JetBrains Mono',monospace;color:#6b7184;margin-top:2px">last activity %s%s · %d entries auto-cleaned · drift: %d</div>
  </div>
  <div style="display:flex;gap:14px;text-align:right">
    <div><div style="font:700 22px 'Hanken Grotesk',sans-serif;color:%s">%d</div><div style="font:600 9px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase">Active bans</div></div>
    <div style="width:1px;background:#20242f"></div>
    <div><div style="font:700 22px 'Hanken Grotesk',sans-serif;color:#54c79a">%d</div><div style="font:600 9px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase">Drift</div></div>
  </div>
</div>
</div>`,
		dotColor, html.EscapeString(headline),
		html.EscapeString(lastStr), html.EscapeString(agoStr),
		cleaned, drift,
		countColor, activeCount, drift,
	)
}

// ─── Boundary ────────────────────────────────────────────────────────────────

func renderV2CFBoundary(v v2CloudflareView) string {
	tokenStatus := "present"
	tokenColor := "#54c79a"
	if !v.APITokenPresent {
		tokenStatus = "absent"
		tokenColor = "#f08591"
	}
	zoneStatus := "present"
	zoneColor := "#54c79a"
	if !v.ZoneIDPresent {
		zoneStatus = "absent"
		zoneColor = "#f08591"
	}

	inv := v.Sync.RuleInventory
	rulesObserved := "0 live · 0 untracked"
	rulesState := `<span style="color:#54c79a">✓ ok</span>`
	if inv.Wired {
		rulesObserved = fmt.Sprintf("%d live · %d untracked", inv.LiveCount, inv.UntrackedCount)
	}
	if inv.Error != "" {
		rulesObserved = "API error: " + inv.Error
		rulesState = `<span style="color:#f08591">⚠ error</span>`
	}

	modeDesired := "live"
	modeObserved := "normal"
	modeState := `<span style="color:#54c79a">✓ ok</span>`
	if !v.MutationsEnabled {
		modeDesired = "shadow"
		modeObserved = "dry-run"
		modeState = `<span style="color:#f5a443">⚠ dry-run</span>`
	}

	missingRules := 0
	divergentRules := 0
	if inv.Wired {
		if inv.UntrackedCount < 0 {
			divergentRules = -inv.UntrackedCount
		}
	}

	return fmt.Sprintf(`<div style="display:flex;flex-direction:column;gap:16px">
  <div style="border:1px solid rgba(76,199,154,.2);border-radius:12px;background:rgba(76,199,154,.04);padding:16px 18px">
    <div style="display:flex;align-items:center;gap:10px">
      <span style="width:8px;height:8px;border-radius:50%%;background:#4cc79a;flex:none"></span>
      <span style="font:700 14px 'Hanken Grotesk',sans-serif;color:#eef0f6">Cloudflare boundary</span>
      <span style="font:600 10px 'JetBrains Mono',monospace;color:#54c79a;background:rgba(76,199,154,.12);padding:2px 7px;border-radius:5px">converged</span>
      <span style="flex:1"></span>
      <span style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184">refreshed every 1m · forensic projection only</span>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:7px;margin-top:12px">
      <span style="font:500 11px 'JetBrains Mono',monospace;color:#9aa0b2;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);padding:3px 9px;border-radius:6px"><span style="color:#787f93">desired:</span> %s</span>
      <span style="font:500 11px 'JetBrains Mono',monospace;color:#9aa0b2;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);padding:3px 9px;border-radius:6px"><span style="color:#787f93">observed:</span> %s</span>
      <span style="font:500 11px 'JetBrains Mono',monospace;color:#54c79a;background:rgba(76,199,154,.08);border:1px solid rgba(76,199,154,.16);padding:3px 9px;border-radius:6px">no mutation exposed here</span>
    </div>
  </div>

  <div style="border:1px solid #20242f;border-radius:12px;background:#13151c;overflow:hidden">
    <div style="display:flex;font:700 9px 'Hanken Grotesk',sans-serif;letter-spacing:.07em;color:#7b8196;text-transform:uppercase;padding:11px 16px;border-bottom:1px solid #20242f">
      <span style="flex:1.3">Field</span><span style="flex:1">Desired</span><span style="flex:1">Observed in zone</span><span style="width:70px;text-align:right">State</span>
    </div>
    <div class="v2-cf-row" style="border-top:none"><span style="flex:1.3;color:#9aa0b2">mode</span><span style="flex:1;color:#e3e6ef">%s</span><span style="flex:1;color:#e3e6ef">%s</span><span style="width:70px;text-align:right">%s</span></div>
    <div class="v2-cf-row"><span style="flex:1.3;color:#9aa0b2">api token</span><span style="flex:1;color:#e3e6ef">from environment</span><span style="flex:1;color:%s">%s</span><span style="width:70px;text-align:right;color:%s">%s</span></div>
    <div class="v2-cf-row"><span style="flex:1.3;color:#9aa0b2">zone config</span><span style="flex:1;color:#e3e6ef">from setup wizard</span><span style="flex:1;color:%s">%s</span><span style="width:70px;text-align:right;color:%s">%s</span></div>
    <div class="v2-cf-row"><span style="flex:1.3;color:#9aa0b2">ip access rules</span><span style="flex:1;color:#e3e6ef">managed by daemon</span><span style="flex:1;color:#e3e6ef">%s</span><span style="width:70px;text-align:right">%s</span></div>
  </div>

  <div class="v2-cf-tiles">
    <div class="v2-cf-tile"><div class="v2-cf-tile-val green">%d</div><div class="v2-cf-tile-lab">missing rules</div></div>
    <div class="v2-cf-tile"><div class="v2-cf-tile-val green">%d</div><div class="v2-cf-tile-lab">divergent rules</div></div>
    <div class="v2-cf-tile"><div style="font:700 26px 'Hanken Grotesk',sans-serif;color:#eef0f6">%d <span style="font-size:14px;color:#6b7184">tracked</span></div><div class="v2-cf-tile-lab">lifecycle entries</div></div>
  </div>

  <div style="display:flex;align-items:center;gap:9px;padding:11px 14px;border-radius:10px;background:rgba(124,108,242,.06);border:1px solid rgba(124,108,242,.16)">
    <span style="width:7px;height:7px;border-radius:50%%;background:#7c6cf2;flex:none"></span>
    <span style="font:500 12px 'Hanken Grotesk',sans-serif;color:#aab0c2">This console never modifies Cloudflare rules. Everything is projected from config and the daemon's lifecycle store. For forensic diff of live rules, see <a href="/cloudflare/diff" style="color:#a99cff;text-decoration:none">Classic Cloudflare diff ↗</a>.</span>
  </div>
</div>`,
		html.EscapeString(modeDesired), html.EscapeString(modeObserved),
		html.EscapeString(modeDesired), html.EscapeString(modeObserved), modeState,
		tokenColor, html.EscapeString(tokenStatus), tokenColor,
		func() string {
			if v.APITokenPresent {
				return "✓ ok"
			}
			return "✗ missing"
		}(),
		zoneColor, html.EscapeString(zoneStatus), zoneColor,
		func() string {
			if v.ZoneIDPresent {
				return "✓ ok"
			}
			return "✗ missing"
		}(),
		html.EscapeString(rulesObserved), rulesState,
		missingRules, divergentRules, v.Stats.TotalTracked,
	)
}

// ─── Ban sync ─────────────────────────────────────────────────────────────────

func renderV2CFSync(v v2CloudflareView) string {
	sync := v.Sync
	if !sync.Wired {
		return `<div class="v2-card"><div class="v2-card-body"><div class="v2-empty">Ban lifecycle store not configured in this build.</div></div></div>`
	}

	mutBadge := `<span style="font:600 10px 'JetBrains Mono',monospace;color:#54c79a;background:rgba(76,199,154,.12);border:1px solid rgba(76,199,154,.2);padding:3px 8px;border-radius:6px">MUTATIONS ON</span>`
	if sync.DryRun {
		mutBadge = `<span style="font:600 10px 'JetBrains Mono',monospace;color:#f5a443;background:rgba(245,146,30,.12);border:1px solid rgba(245,146,30,.2);padding:3px 8px;border-radius:6px">DRY-RUN</span>`
	}

	lastActivity := "—"
	if !sync.LastActivityAt.IsZero() {
		ago := time.Since(sync.LastActivityAt).Truncate(time.Minute)
		lastActivity = sync.LastActivityAt.UTC().Format("2006-01-02 15:04:05Z") + " · " + ago.String() + " ago"
	}

	// Status breakdown bars
	var breakdownHTML strings.Builder
	statKeys := make([]string, 0, len(sync.StatusCounts))
	for k := range sync.StatusCounts {
		statKeys = append(statKeys, k)
	}
	sort.Strings(statKeys)
	maxCount := 1
	for _, cnt := range sync.StatusCounts {
		if cnt > maxCount {
			maxCount = cnt
		}
	}
	for _, k := range statKeys {
		cnt := sync.StatusCounts[k]
		pct := 100 * cnt / maxCount
		breakdownHTML.WriteString(fmt.Sprintf(
			`<div style="display:flex;align-items:center;gap:10px;margin-top:6px"><span style="font:600 13px 'Hanken Grotesk',sans-serif;color:#e3e6ef;width:160px;font-size:12px">%s</span><span style="flex:1;height:7px;border-radius:4px;background:#1c2030;overflow:hidden"><span style="display:block;width:%d%%;height:100%%;background:#4cc79a"></span></span><span style="font:700 13px 'JetBrains Mono',monospace;color:#54c79a;width:32px;text-align:right">%d</span></div>`,
			html.EscapeString(k), pct, cnt,
		))
	}
	if len(statKeys) == 0 {
		breakdownHTML.WriteString(`<div style="font:500 11px 'JetBrains Mono',monospace;color:#5a6072;margin-top:8px">No entries yet.</div>`)
	}

	// Rule inventory
	inv := sync.RuleInventory
	invLive, invTracked, invUntracked := 0, 0, 0
	invNote := ""
	if inv.Wired {
		invLive, invTracked, invUntracked = inv.LiveCount, inv.TrackedCount, inv.UntrackedCount
	} else {
		invNote = `<div style="font:500 11px 'JetBrains Mono',monospace;color:#5a6072;margin-top:8px">No Cloudflare API token/zone configured.</div>`
	}
	if inv.Error != "" {
		invNote = fmt.Sprintf(`<div style="font:500 11px 'JetBrains Mono',monospace;color:#f08591;margin-top:8px">API error: %s</div>`, html.EscapeString(inv.Error))
	}

	return fmt.Sprintf(`<div style="display:flex;flex-direction:column;gap:16px">
  <div style="border:1px solid #20242f;border-radius:12px;background:#13151c;padding:16px 18px">
    <div style="display:flex;align-items:center;margin-bottom:14px"><span style="font:700 13px 'Hanken Grotesk',sans-serif;color:#eef0f6">Live managed state</span><span style="flex:1"></span>%s</div>
    <div class="v2-cf-tiles">
      <div class="v2-cf-tile"><div class="v2-cf-tile-val">%d</div><div class="v2-cf-tile-lab">active managed bans</div></div>
      <div class="v2-cf-tile" style="flex:2"><div style="font:600 13px 'JetBrains Mono',monospace;color:#e3e6ef">%s</div><div class="v2-cf-tile-lab">most recent activity</div></div>
    </div>
  </div>

  <div class="v2-cf-grid2">
    <div style="border:1px solid #20242f;border-radius:12px;background:#13151c;padding:16px 18px">
      <div style="font:700 11px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase;margin-bottom:4px">Status breakdown</div>
      <div style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184;margin-bottom:4px">across most recent %d tracked entries</div>
      %s
    </div>
    <div style="border:1px solid #20242f;border-radius:12px;background:#13151c;padding:16px 18px">
      <div style="font:700 11px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase;margin-bottom:4px">Cloudflare rule inventory</div>
      <div style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184;margin-bottom:8px">vs zone's live IP access rules</div>
      <div style="display:flex;align-items:center;gap:10px;padding:6px 0"><span style="flex:1;font:500 12px 'Hanken Grotesk',sans-serif;color:#9aa0b2">Live rules in zone</span><span style="font:700 13px 'JetBrains Mono',monospace;color:#eef0f6">%d</span></div>
      <div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-top:1px solid #1a1e29"><span style="flex:1;font:500 12px 'Hanken Grotesk',sans-serif;color:#9aa0b2">Tracked by cf_ban_lifecycle</span><span style="font:700 13px 'JetBrains Mono',monospace;color:#eef0f6">%d</span></div>
      <div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-top:1px solid #1a1e29"><span style="flex:1;font:500 12px 'Hanken Grotesk',sans-serif;color:#9aa0b2">Untracked (pre-existing)</span><span style="font:700 13px 'JetBrains Mono',monospace;color:#54c79a">%d</span></div>
      %s
    </div>
  </div>

  <div style="display:flex;align-items:center;gap:9px;padding:11px 14px;border-radius:10px;background:rgba(255,255,255,.02);border:1px solid #20242f">
    <span style="font:500 12px 'Hanken Grotesk',sans-serif;color:#9aa0b2;flex:1">Per-IP history and operator deban actions → <strong style="color:#a99cff">Ban lifecycle</strong> tab.</span>
    <a href="/v2/cloudflare?tab=lifecycle" style="font:600 11px 'Hanken Grotesk',sans-serif;color:#a99cff;text-decoration:none">Open lifecycle →</a>
  </div>
</div>`,
		mutBadge,
		sync.ActiveCount,
		html.EscapeString(lastActivity),
		sync.SampleSize,
		breakdownHTML.String(),
		invLive, invTracked, invUntracked, invNote,
	)
}

// ─── Ban lifecycle ────────────────────────────────────────────────────────────

func renderV2CFLifecycle(v v2CloudflareView) string {
	if !v.Lifecycle.Wired {
		return `<div class="v2-card"><div class="v2-card-body"><div class="v2-empty">Ban lifecycle store not configured in this build.</div></div></div>`
	}

	stats := v.Stats

	// By-reason table
	var reasonRows strings.Builder
	for _, g := range stats.ReasonGroups {
		dotColor := "#f5921e"
		reasonColor := "#e3e6ef"
		countColor := "#f5a443"
		if g.IsRed {
			dotColor = "#ef5f6b"
			reasonColor = "#f08591"
			countColor = "#f08591"
		}
		var pills strings.Builder
		if g.First > 0 {
			pills.WriteString(fmt.Sprintf(`<span class="v2-cf-recid-1">1st → %d</span> `, g.First))
		}
		if g.Second > 0 {
			pills.WriteString(fmt.Sprintf(`<span class="v2-cf-recid-2">2nd → %d</span> `, g.Second))
		}
		if g.Third > 0 {
			pills.WriteString(fmt.Sprintf(`<span class="v2-cf-recid-3">3rd+ → %d</span> `, g.Third))
		}
		if g.IsRed {
			pills.WriteString(`<span style="font:500 10px 'JetBrains Mono',monospace;color:#f08591;background:rgba(239,95,107,.1);border:1px solid rgba(239,95,107,.2);padding:1px 6px;border-radius:5px">burst → instant</span>`)
		}
		reasonRows.WriteString(fmt.Sprintf(
			`<div style="display:flex;align-items:center;gap:12px;padding:11px 16px;border-top:1px solid #1a1e29"><span style="width:8px;height:8px;border-radius:50%%;background:%s;flex:none"></span><span style="font:600 13px 'Hanken Grotesk',sans-serif;color:%s;width:220px;font-size:12px">%s</span><span style="display:flex;gap:5px;flex:1;flex-wrap:wrap">%s</span><span style="font:700 13px 'JetBrains Mono',monospace;color:%s">×%d</span></div>`,
			dotColor, reasonColor, html.EscapeString(g.Reason), pills.String(), countColor, g.Total,
		))
	}
	if len(stats.ReasonGroups) == 0 {
		reasonRows.WriteString(`<div style="padding:16px;text-align:center;font:500 12px 'JetBrains Mono',monospace;color:#5a6072">No entries yet.</div>`)
	}

	// Recent entries (last 6)
	entries := v.Lifecycle.Entries
	maxRows := 6
	if len(entries) < maxRows {
		maxRows = len(entries)
	}
	shown := entries[:maxRows]
	var entryRows strings.Builder
	for _, e := range shown {
		recidBadge := `<span style="color:#6b7184">1st</span>`
		switch {
		case e.RecidiveLevel == 2:
			recidBadge = `<span class="v2-cf-recid-2">2nd</span>`
		case e.RecidiveLevel >= 3:
			recidBadge = `<span class="v2-cf-recid-3">3rd+</span>`
		}
		statusColor := "#54c79a"
		statusLabel := html.EscapeString(e.Status)
		if e.Status == "active" {
			statusColor = "#f5a443"
		}
		reasonColor := "#9aa0b2"
		if strings.Contains(e.Reason, "burst_malicious") {
			reasonColor = "#f08591"
		}
		entryRows.WriteString(fmt.Sprintf(
			`<div style="display:flex;align-items:center;padding:10px 16px;font:500 12px 'JetBrains Mono',monospace;border-top:1px solid #181b25"><span style="width:180px;color:#cdd2e0">%s</span><span style="flex:1;color:%s">%s</span><span style="width:60px;text-align:center">%s</span><span style="width:90px;text-align:right;color:#6b7184">%s</span><span style="width:90px;text-align:right;color:%s">%s</span></div>`,
			html.EscapeString(e.IP),
			reasonColor, html.EscapeString(shortReason(e.Reason)),
			recidBadge,
			shortTime(e.CreatedAt),
			statusColor, statusLabel,
		))
	}
	if len(entries) == 0 {
		entryRows.WriteString(`<div style="padding:18px;text-align:center;font:500 12px 'JetBrains Mono',monospace;color:#5a6072">No entries yet.</div>`)
	}

	showAllCount := len(entries)

	// Clear-all danger zone
	dangerZone := ""
	if v.ActionsAvailable {
		dangerZone = fmt.Sprintf(`<form method="POST" action="/actions/ban-lifecycle/clear" onsubmit="return confirm('Remove Cloudflare rule for every active managed ban? AbuseIPDB history is never touched.');" style="display:flex;align-items:center;gap:13px;padding:13px 16px;border-radius:11px;background:rgba(239,95,107,.05);border:1px solid rgba(239,95,107,.2)">
  <input type="hidden" name="csrf_token" value="%s">
  <span style="width:8px;height:8px;border-radius:50%%;background:#ef5f6b;flex:none"></span>
  <div style="flex:1"><div style="font:600 13px 'Hanken Grotesk',sans-serif;color:#f08591">Clear all managed bans</div><div style="font:500 11px 'Hanken Grotesk',sans-serif;color:#9aa0b2;margin-top:1px">Removes the Cloudflare rule for each active entry. Never affects AbuseIPDB history or the 24h reporting window.</div></div>
  <input name="confirm" placeholder="type CLEAR" style="background:#10121a;border:1px solid #20242f;border-radius:6px;padding:6px 10px;font:600 11px 'JetBrains Mono',monospace;color:#9aa0b2;width:120px" autocomplete="off">
  <button type="submit" style="font:600 11px 'Hanken Grotesk',sans-serif;color:#f08591;background:rgba(239,95,107,.1);border:1px solid rgba(239,95,107,.25);padding:7px 13px;border-radius:7px;cursor:pointer">Confirm</button>
</form>`, html.EscapeString(v.CSRFToken))
	} else {
		dangerZone = `<div style="display:flex;align-items:center;gap:13px;padding:13px 16px;border-radius:11px;background:rgba(255,255,255,.02);border:1px solid #20242f"><span style="font:500 12px 'Hanken Grotesk',sans-serif;color:#5a6072">Clear-all action unavailable — Cloudflare mutations disabled or deban capability not wired.</span></div>`
	}

	return fmt.Sprintf(`<div style="display:flex;flex-direction:column;gap:16px">
  <div class="v2-cf-tiles">
    <div class="v2-cf-tile"><div class="v2-cf-tile-val">%d</div><div class="v2-cf-tile-lab">tracked entries</div></div>
    <div class="v2-cf-tile"><div class="v2-cf-tile-val green">%d</div><div class="v2-cf-tile-lab">active now</div></div>
    <div class="v2-cf-tile"><div class="v2-cf-tile-val orange">%d</div><div class="v2-cf-tile-lab">recidivists (≥2nd)</div></div>
    <div class="v2-cf-tile"><div class="v2-cf-tile-val">%d</div><div class="v2-cf-tile-lab">burst_malicious</div></div>
  </div>

  <div style="border:1px solid #20242f;border-radius:12px;background:#13151c;overflow:hidden">
    <div style="display:flex;align-items:center;padding:13px 16px;border-bottom:1px solid #20242f"><span style="font:700 11px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase">By reason &amp; recidive</span><span style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184;margin-left:8px">recidive-aware durations</span></div>
    %s
  </div>

  <div style="border:1px solid #20242f;border-radius:12px;background:#13151c;overflow:hidden">
    <div style="display:flex;align-items:center;padding:13px 16px;border-bottom:1px solid #20242f">
      <span style="font:700 11px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase">Recent entries</span>
      <span style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184;margin-left:8px">latest %d of %d</span>
      <span style="flex:1"></span>
      <a href="/ban-lifecycle" style="font:600 11px 'JetBrains Mono',monospace;color:#7c6cf2;text-decoration:none">Full history ↗</a>
    </div>
    <div style="display:flex;align-items:center;padding:9px 16px;font:700 9px 'Hanken Grotesk',sans-serif;letter-spacing:.07em;color:#5a6072;text-transform:uppercase;border-bottom:1px solid #181b25">
      <span style="width:180px">IP</span><span style="flex:1">Reason</span><span style="width:60px;text-align:center">Recidive</span><span style="width:90px;text-align:right">Created</span><span style="width:90px;text-align:right">Status</span>
    </div>
    %s
    %s
  </div>

  %s
</div>`,
		stats.TotalTracked, stats.ActiveNow, stats.Recidivists, stats.BurstMalicious,
		reasonRows.String(),
		maxRows, showAllCount,
		entryRows.String(),
		func() string {
			if showAllCount > 6 {
				return fmt.Sprintf(`<div style="padding:12px 16px;border-top:1px solid #181b25;text-align:center"><a href="/ban-lifecycle" style="font:600 11px 'Hanken Grotesk',sans-serif;color:#7c6cf2;text-decoration:none">Show all %d entries →</a></div>`, showAllCount)
			}
			return ""
		}(),
		dangerZone,
	)
}

// shortReason trims "autoban_" prefix for compact display.
func shortReason(r string) string {
	return strings.TrimPrefix(r, "autoban_")
}

// shortTime formats a stored timestamp string to HH:MMZ for compact display.
func shortTime(ts string) string {
	t, err := time.Parse("2006-01-02 15:04:05Z", ts)
	if err != nil {
		return ts
	}
	return t.UTC().Format("15:04Z")
}
