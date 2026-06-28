package ui

import (
	"fmt"
	"html"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/security/enrichment"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

// handleV2Investigate serves GET /v2/investigate.
// Without ?ip= (or ?q=): shows search hero + recent evidence grouped by IP.
// With ?ip=<ip>: shows enrichment + signal tiles + decision history.
func (s *Server) handleV2Investigate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()

	q := strings.TrimSpace(r.URL.Query().Get("ip"))
	if q == "" {
		q = strings.TrimSpace(r.URL.Query().Get("q"))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fromPage := strings.TrimSpace(r.URL.Query().Get("from"))

	if q == "" {
		var recentEntries []reporting.DecisionEvidence
		if s.evidence != nil {
			recentEntries, _ = s.evidence.Search(ctx, reporting.EvidenceSearchOptions{Limit: 100})
		}
		_, _ = fmt.Fprint(w, v2Page("Investigate", "/v2/investigate", renderV2InvestigateEmpty(recentEntries)))
		return
	}

	ip, err := netip.ParseAddr(q)
	if err != nil || !ip.IsValid() {
		var recentEntries []reporting.DecisionEvidence
		if s.evidence != nil {
			recentEntries, _ = s.evidence.Search(ctx, reporting.EvidenceSearchOptions{Limit: 100})
		}
		content := renderV2InvestigateInvalidIP(q) + renderV2InvestigateEmpty(recentEntries)
		_, _ = fmt.Fprint(w, v2Page("Investigate", "/v2/investigate", content))
		return
	}

	ipStr := ip.String()
	view := ForensicView{IP: ipStr}
	if svc := s.securityIntelligenceService(); svc != nil {
		summary, enrichErr := svc.Enrich(ctx, ip, enrichment.LookupOptions{ManualForensics: true})
		if enrichErr == nil {
			view.Summary = summary
			view.Assess = svc.Assess(summary)
			view.HasEnrichment = true
		} else {
			view.EnrichmentError = fmt.Sprintf("enrichment failed: %v", enrichErr)
		}
	}

	var ipEvidence []reporting.DecisionEvidence
	if s.evidence != nil {
		ipEvidence, _ = s.evidence.Search(ctx, reporting.EvidenceSearchOptions{IP: ipStr, Limit: 50})
	}

	var noteContent string
	if s.noteStore != nil {
		existing, _, _ := s.noteStore.Get(ctx, "ip", ipStr)
		noteContent = existing.Content
	}

	s.audit.Record("forensic_lookup", map[string]string{"ip": ipStr, "source": "ui_v2"})

	_, _ = fmt.Fprint(w, v2Page("Investigate · "+html.EscapeString(ipStr), "/v2/investigate",
		renderV2InvestigateIP(view, ipEvidence, noteContent, s.csrfTokenFromRequest(r), fromPage)))
}

// ipEvidenceGroup aggregates evidence records for a single IP.
type ipEvidenceGroup struct {
	IP        string
	Behaviour string
	Score     int
	Decision  string
	Events    int
	LastSeen  time.Time
}

// groupEvidenceByIP collapses a flat evidence list into per-IP summaries.
func groupEvidenceByIP(entries []reporting.DecisionEvidence) []ipEvidenceGroup {
	type acc struct {
		scores   []int
		types    map[string]int
		decision string
		lastSeen time.Time
		count    int
	}
	byIP := map[string]*acc{}
	order := []string{}

	for _, ev := range entries {
		a, ok := byIP[ev.IP]
		if !ok {
			a = &acc{types: map[string]int{}}
			byIP[ev.IP] = a
			order = append(order, ev.IP)
		}
		a.count++
		a.scores = append(a.scores, ev.RiskScore)
		if ev.AbuseType != "" {
			a.types[ev.AbuseType]++
		}
		if ev.Timestamp.After(a.lastSeen) {
			a.lastSeen = ev.Timestamp
			a.decision = ev.Decision
		}
	}

	result := make([]ipEvidenceGroup, 0, len(order))
	for _, ip := range order {
		a := byIP[ip]
		maxScore := 0
		for _, s := range a.scores {
			if s > maxScore {
				maxScore = s
			}
		}
		topType := ""
		topCount := 0
		for t, c := range a.types {
			if c > topCount {
				topCount = c
				topType = t
			}
		}
		result = append(result, ipEvidenceGroup{
			IP:        ip,
			Behaviour: topType,
			Score:     maxScore,
			Decision:  a.decision,
			Events:    a.count,
			LastSeen:  a.lastSeen,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].LastSeen.After(result[j].LastSeen)
	})
	return result
}

// renderV2InvestigateEmpty renders State A: search hero + grouped evidence feed + secondary panels.
func renderV2InvestigateEmpty(recent []reporting.DecisionEvidence) string {
	var b strings.Builder

	b.WriteString(`
<div class="v2-topbar">
  <span class="v2-topbar-title">Investigate</span>
  <span style="flex:1"></span>
  <span class="v2-live-badge"><span class="v2-live-dot"></span>LIVE</span>
</div>
`)

	groups := groupEvidenceByIP(recent)

	// Two-column layout: main (search + evidence) | sidebar (top attackers + quick nav)
	b.WriteString(`<div style="display:grid;grid-template-columns:1fr 300px;gap:16px;align-items:start">`)

	// ── Left column ────────────────────────────────────────────────────────
	b.WriteString(`<div>`)

	// Search hero
	b.WriteString(`<div class="v2-card" style="margin-bottom:16px">
  <div class="v2-card-body" style="padding:24px">
    <div style="font:800 20px 'Hanken Grotesk',sans-serif;color:#eef0f6;margin-bottom:3px">Investigate an IP</div>
    <div style="font:500 12px 'JetBrains Mono',monospace;color:#6b7184;margin-bottom:16px">Enrichment, evidence, and decision history in one view.</div>
    <form method="GET" action="/v2/investigate" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <input type="text" name="ip" placeholder="e.g. 1.2.3.4"
        style="flex:1;min-width:180px;background:#0d0f14;border:1px solid #2a2f42;border-radius:8px;padding:8px 13px;color:#eef0f6;font:500 13px 'JetBrains Mono',monospace;outline:none"
        autocomplete="off" autocorrect="off" spellcheck="false">
      <button type="submit"
        style="padding:8px 16px;background:#7c6cf2;border:none;border-radius:8px;color:#fff;font:700 12px 'Hanken Grotesk',sans-serif;cursor:pointer;white-space:nowrap">
        Open incident →
      </button>
    </form>
  </div>
</div>`)

	// Grouped evidence table
	b.WriteString(`<div class="v2-card">
  <div class="v2-card-header">
    <span class="v2-card-title">Recent evidence</span>
    <span style="flex:1"></span>
    <span style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184">grouped by IP · click to investigate</span>
  </div>
`)

	if len(groups) == 0 {
		b.WriteString(`<div class="v2-empty">No evidence recorded yet.</div>`)
	} else {
		b.WriteString(`<div class="v2-table-wrap"><table class="v2-table">
<thead><tr>
  <th>Source IP</th><th>Behaviour</th><th>Score</th><th>Decision</th><th>Events</th><th>Last seen</th>
</tr></thead><tbody>`)
		for _, g := range groups {
			behaviour := g.Behaviour
			if behaviour == "" {
				behaviour = "—"
			}
			lastSeen := ""
			if !g.LastSeen.IsZero() {
				lastSeen = g.LastSeen.UTC().Format("2006-01-02 15:04")
			}
			scoreColor := "#c5cad8"
			if g.Score >= 80 {
				scoreColor = "#f08591"
			} else if g.Score >= 50 {
				scoreColor = "#f5a443"
			}
			b.WriteString(fmt.Sprintf(`<tr style="cursor:pointer" onclick="location.href='/v2/investigate?ip=%s'">
  <td><a href="/v2/investigate?ip=%s" onclick="event.stopPropagation()" style="color:#7c6cf2;font-family:'JetBrains Mono',monospace">%s</a></td>
  <td>%s</td>
  <td style="color:%s;font-family:'JetBrains Mono',monospace;font-weight:600">%d</td>
  <td>%s</td>
  <td style="color:#9aa0b2">%d</td>
  <td style="color:#6b7184;font-size:11px">%s</td>
</tr>`,
				url.QueryEscape(g.IP),
				url.QueryEscape(g.IP), html.EscapeString(g.IP),
				html.EscapeString(behaviour),
				scoreColor, g.Score,
				html.EscapeString(g.Decision),
				g.Events,
				html.EscapeString(lastSeen),
			))
		}
		b.WriteString(`</tbody></table></div>`)
	}
	b.WriteString(`</div>`)
	b.WriteString(`</div>`) // end left column

	// ── Right column: secondary panels ─────────────────────────────────────
	b.WriteString(`<div>`)

	// Top attackers KV panel
	b.WriteString(`<div class="v2-card" style="margin-bottom:16px">
  <div class="v2-card-header"><span class="v2-card-title">Top attackers</span></div>
  <div class="v2-card-body" style="padding:10px 18px">`)
	if len(groups) == 0 {
		b.WriteString(`<div style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184;padding:8px 0">No data yet.</div>`)
	} else {
		// Sort by event count descending for top attackers panel
		sorted := make([]ipEvidenceGroup, len(groups))
		copy(sorted, groups)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Events > sorted[j].Events })
		limit := 8
		if len(sorted) < limit {
			limit = len(sorted)
		}
		b.WriteString(`<div class="v2-kv">`)
		for _, g := range sorted[:limit] {
			scoreClass := ""
			if g.Score >= 80 {
				scoreClass = "error"
			} else if g.Score >= 50 {
				scoreClass = "warn"
			}
			b.WriteString(fmt.Sprintf(
				`<div class="v2-kv-row"><span class="v2-kv-key"><a href="/v2/investigate?ip=%s" style="color:#7c6cf2;text-decoration:none;font:inherit">%s</a></span>`+
					`<span class="v2-kv-val" style="flex:none"><span class="v2-chip %s">%d evt</span></span></div>`,
				url.QueryEscape(g.IP), html.EscapeString(g.IP),
				scoreClass, g.Events,
			))
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div></div>`) // end top-attackers card

	// Quick nav panel
	b.WriteString(`<div class="v2-card">
  <div class="v2-card-header"><span class="v2-card-title">Quick nav</span></div>
  <div class="v2-card-body" style="padding:10px 18px">
    <div class="v2-kv">
      <div class="v2-kv-row"><a href="/v2/timeline" style="color:#7c6cf2;text-decoration:none;font:500 12px 'Hanken Grotesk',sans-serif">Browse timeline →</a></div>
      <div class="v2-kv-row"><a href="/v2/timeline?q=waf" style="color:#9aa0b2;text-decoration:none;font:500 12px 'Hanken Grotesk',sans-serif">WAF events →</a></div>
      <div class="v2-kv-row"><a href="/v2/timeline?q=abuseipdb" style="color:#9aa0b2;text-decoration:none;font:500 12px 'Hanken Grotesk',sans-serif">AbuseIPDB reports →</a></div>
      <div class="v2-kv-row"><a href="/v2/notes" style="color:#9aa0b2;text-decoration:none;font:500 12px 'Hanken Grotesk',sans-serif">Operator notes →</a></div>
      <div class="v2-kv-row"><a href="/v2/cloudflare" style="color:#9aa0b2;text-decoration:none;font:500 12px 'Hanken Grotesk',sans-serif">Cloudflare boundary →</a></div>
    </div>
  </div>
</div>`)

	b.WriteString(`</div>`) // end right column
	b.WriteString(`</div>`) // end grid

	return b.String()
}

func renderV2InvestigateInvalidIP(q string) string {
	return fmt.Sprintf(`<div style="margin-bottom:14px;padding:10px 14px;border:1px solid rgba(239,95,107,.24);border-radius:8px;background:rgba(239,95,107,.08);font:500 13px 'JetBrains Mono',monospace;color:#f08591">Not a valid IP address: %s</div>`,
		html.EscapeString(q))
}

// renderV2InvestigateIP renders State B: incident header + signal tiles + two-column layout.
func renderV2InvestigateIP(view ForensicView, ipEvidence []reporting.DecisionEvidence, noteContent, csrfToken, fromPage string) string {
	var b strings.Builder
	ip := html.EscapeString(view.IP)
	ipQ := url.QueryEscape(view.IP)

	// Back-navigation banner when arriving from another page (#168)
	if fromPage == "timeline" {
		b.WriteString(fmt.Sprintf(
			`<a href="/v2/timeline?q=%s" style="display:inline-flex;align-items:center;gap:6px;padding:5px 12px;border-radius:6px;background:rgba(124,108,242,.1);border:1px solid rgba(124,108,242,.22);font:600 12px 'Hanken Grotesk',sans-serif;color:#9b8cff;text-decoration:none;margin-bottom:14px">← Timeline · results for %s</a>`,
			ipQ, ip,
		))
	}

	// Build subtitle from geo / ASN
	var subtitleParts []string
	if view.HasEnrichment {
		for _, p := range view.Summary.Providers {
			if p.Provider == "abuseipdb" {
				if cc := v2NoteExtract(p.Note, "country"); cc != "" {
					subtitleParts = append(subtitleParts, cc)
				}
				break
			}
		}
		if view.Summary.ASN.Network != "" {
			subtitleParts = append(subtitleParts, view.Summary.ASN.Network)
		} else if view.Summary.ASN.Org != "" {
			subtitleParts = append(subtitleParts, view.Summary.ASN.Org)
		}
	}
	subtitle := strings.Join(subtitleParts, " · ")

	// Verdict badge
	verdictLabel, verdictColor, verdictBG := "UNKNOWN", "#9aa0b2", "rgba(154,160,178,.1)"
	if view.HasEnrichment {
		switch {
		case view.Assess.HardBanAllowed && !view.Assess.NoHardBan:
			verdictLabel, verdictColor, verdictBG = "THREAT", "#f08591", "rgba(239,95,107,.12)"
		case view.Assess.NoHardBan:
			verdictLabel, verdictColor, verdictBG = "PROTECTED", "#4cc79a", "rgba(76,199,154,.12)"
		case view.Assess.Score > 20:
			verdictLabel, verdictColor, verdictBG = "SUSPICIOUS", "#f5a443", "rgba(245,164,67,.12)"
		}
	}

	// Incident header
	b.WriteString(fmt.Sprintf(`
<div style="display:flex;align-items:center;gap:10px;margin-bottom:20px;flex-wrap:wrap">
  <a href="/v2/investigate" style="color:#6b7184;text-decoration:none;font:500 13px 'Hanken Grotesk',sans-serif;padding:5px 10px;border:1px solid #20242f;border-radius:7px">← Back</a>
  <span style="font:700 15px 'JetBrains Mono',monospace;color:#eef0f6;padding:4px 10px;background:#1a1e29;border:1px solid #2a2f42;border-radius:7px">%s</span>
  <span style="padding:3px 9px;border-radius:5px;background:%s;font:700 11px 'JetBrains Mono',monospace;color:%s;letter-spacing:.06em">%s</span>
  %s
  <span style="flex:1"></span>
  <a href="/v2/incident?ip=%s" style="padding:6px 14px;background:rgba(124,108,242,.15);border:1px solid rgba(124,108,242,.3);border-radius:7px;color:#9b8cff;text-decoration:none;font:600 12px 'Hanken Grotesk',sans-serif">◎ Focus Incident</a>
  <a href="/v2/timeline?q=%s" style="padding:6px 14px;background:rgba(255,255,255,.04);border:1px solid #20242f;border-radius:7px;color:#c5cad8;text-decoration:none;font:600 12px 'Hanken Grotesk',sans-serif">⟳ Timeline</a>
</div>
`,
		ip,
		verdictBG, verdictColor, verdictLabel,
		func() string {
			if subtitle == "" {
				return ""
			}
			return fmt.Sprintf(`<span style="color:#6b7184;font:500 12px 'Hanken Grotesk',sans-serif">%s</span>`, html.EscapeString(subtitle))
		}(),
		ipQ, ipQ,
	))

	if view.Error != "" {
		b.WriteString(fmt.Sprintf(`<div style="margin-bottom:14px;padding:10px 14px;border:1px solid rgba(239,95,107,.24);border-radius:8px;background:rgba(239,95,107,.08);font:500 13px 'JetBrains Mono',monospace;color:#f08591">%s</div>`,
			html.EscapeString(view.Error)))
	}

	// Signal tiles
	abuseScore, vtScore := -1, -1
	if view.HasEnrichment {
		for _, p := range view.Summary.Providers {
			switch p.Provider {
			case "abuseipdb":
				abuseScore = p.Score
			case "virustotal":
				vtScore = p.Score
			}
		}
	}
	localScore := 0
	if view.HasEnrichment {
		localScore = view.Assess.Score
	}

	b.WriteString(`<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px">`)
	b.WriteString(renderV2SignalTile("AbuseIPDB", abuseScore, 100, "%"))
	b.WriteString(renderV2SignalTile("VirusTotal", vtScore, 100, "%"))
	b.WriteString(renderV2SignalTile("Local score", localScore, -1, "pts"))
	b.WriteString(renderV2SignalTileCount("Events", len(ipEvidence)))
	b.WriteString(`</div>`)

	// Pivot links — direct navigation card (#173)
	b.WriteString(fmt.Sprintf(`<div class="v2-card" style="margin-bottom:16px"><div class="v2-card-header"><span class="v2-card-title">Pivot to</span></div><div class="v2-card-body" style="display:flex;flex-wrap:wrap;gap:8px"><a href="/v2/timeline?q=%s" style="display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:6px;border:1px solid #20242f;background:#10121a;font:600 11px 'JetBrains Mono',monospace;color:#9b8cff;text-decoration:none">⟳ Timeline</a><a href="/v2/cloudflare" style="display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:6px;border:1px solid #20242f;background:#10121a;font:600 11px 'JetBrains Mono',monospace;color:#9b8cff;text-decoration:none">☁ Cloudflare</a><a href="/v2/notes" style="display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:6px;border:1px solid #20242f;background:#10121a;font:600 11px 'JetBrains Mono',monospace;color:#9b8cff;text-decoration:none">✎ Notes</a><a href="/notes?type=ip&amp;value=%s" style="display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:6px;border:1px solid rgba(124,108,242,.3);background:rgba(124,108,242,.08);font:600 11px 'JetBrains Mono',monospace;color:#9b8cff;text-decoration:none">+ Note this IP</a></div></div>`,
		ipQ, ipQ,
	))

	// Two-column layout
	b.WriteString(`<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;align-items:start">`)

	// Left: forensic enrichment
	b.WriteString(`<div>`)
	b.WriteString(renderV2InvestigateEnrichment(view))
	b.WriteString(`</div>`)

	// Right: evidence history + notes
	b.WriteString(`<div>`)
	b.WriteString(renderV2InvestigateHistory(view.IP, ipEvidence))
	if csrfToken != "" {
		b.WriteString(renderV2NoteForm(view.IP, noteContent, csrfToken))
	}
	b.WriteString(`</div>`)

	b.WriteString(`</div>`)
	return b.String()
}

// renderV2SignalTile renders a metric tile. score=-1 means not available.
func renderV2SignalTile(label string, score, outOf int, unit string) string {
	valStr := "—"
	col := "#6b7184"
	if score >= 0 {
		if unit == "%" {
			valStr = fmt.Sprintf("%d%%", score)
		} else {
			valStr = fmt.Sprintf("%d %s", score, unit)
		}
		switch {
		case score >= 80:
			col = "#f08591"
		case score >= 40:
			col = "#f5a443"
		default:
			col = "#4cc79a"
		}
	}
	outOfStr := ""
	if outOf > 0 && score >= 0 {
		outOfStr = fmt.Sprintf(`<span style="color:#3d4355;font-size:11px"> / %d</span>`, outOf)
	}
	return fmt.Sprintf(`<div style="background:#10121a;border:1px solid #20242f;border-radius:10px;padding:14px 16px">
  <div style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184;margin-bottom:6px;text-transform:uppercase;letter-spacing:.06em">%s</div>
  <div style="font:700 22px 'JetBrains Mono',monospace;color:%s">%s%s</div>
</div>`,
		html.EscapeString(label), col, html.EscapeString(valStr), outOfStr)
}

func renderV2SignalTileCount(label string, count int) string {
	col := "#9aa0b2"
	if count > 10 {
		col = "#f5a443"
	} else if count == 0 {
		col = "#4cc79a"
	}
	return fmt.Sprintf(`<div style="background:#10121a;border:1px solid #20242f;border-radius:10px;padding:14px 16px">
  <div style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184;margin-bottom:6px;text-transform:uppercase;letter-spacing:.06em">%s</div>
  <div style="font:700 22px 'JetBrains Mono',monospace;color:%s">%d</div>
</div>`,
		html.EscapeString(label), col, count)
}

// renderV2InvestigateEnrichment renders the left enrichment column.
func renderV2InvestigateEnrichment(view ForensicView) string {
	var b strings.Builder

	b.WriteString(`<div class="v2-card">
  <div class="v2-card-header"><span class="v2-card-title">IP enrichment</span>`)

	if view.HasEnrichment {
		s := view.Summary
		if s.CacheHit {
			b.WriteString(` <span class="v2-pill orange" style="margin-left:auto">cache</span>`)
		} else {
			b.WriteString(` <span class="v2-pill green" style="margin-left:auto">fresh</span>`)
		}
	}
	b.WriteString(`</div>
  <div class="v2-card-body"><div class="v2-kv">`)

	if !view.HasEnrichment {
		if view.EnrichmentError != "" {
			b.WriteString(fmt.Sprintf(`<div class="v2-kv-row"><span class="v2-kv-val" style="color:#6b7184;font-size:12px">%s</span></div>`,
				html.EscapeString(view.EnrichmentError)))
		} else {
			b.WriteString(`<div class="v2-kv-row"><span class="v2-kv-val" style="color:#4a5168;font-style:italic;font-size:13px">Enrichment not configured.</span></div>`)
		}
		b.WriteString(`</div></div></div>`)
		return b.String()
	}

	s := view.Summary
	a := view.Assess

	// rDNS
	dnsVal := `<span style="color:#4a5168">no PTR</span>`
	if s.DNS.Hostname != "" {
		dnsVal = html.EscapeString(s.DNS.Hostname)
		if s.DNS.Confirmed {
			dnsVal += ` <span class="v2-pill green">confirmed</span>`
		} else {
			dnsVal += ` <span class="v2-pill orange">unconfirmed</span>`
		}
		if s.DNS.TrustedBot {
			dnsVal += ` <span class="v2-pill green">trusted bot</span>`
		}
	}
	b.WriteString(fmt.Sprintf(`<div class="v2-kv-row"><span class="v2-kv-key">rDNS</span><span class="v2-kv-val">%s</span></div>`, dnsVal))

	// ASN
	asnVal := `<span style="color:#4a5168">unknown</span>`
	if s.ASN.Org != "" {
		asnVal = html.EscapeString(s.ASN.Org)
		if s.ASN.Network != "" {
			asnVal += fmt.Sprintf(` <span style="color:#6b7184">(%s)</span>`, html.EscapeString(s.ASN.Network))
		}
	}
	b.WriteString(fmt.Sprintf(`<div class="v2-kv-row"><span class="v2-kv-key">ASN</span><span class="v2-kv-val">%s</span></div>`, asnVal))

	// Geo + ISP from AbuseIPDB note
	var geo, isp string
	for _, p := range s.Providers {
		if p.Provider == "abuseipdb" {
			geo = v2NoteExtract(p.Note, "country")
			isp = v2NoteExtract(p.Note, "isp")
			break
		}
	}
	if geo != "" {
		b.WriteString(fmt.Sprintf(`<div class="v2-kv-row"><span class="v2-kv-key">Geo</span><span class="v2-kv-val" style="font-family:'JetBrains Mono',monospace">%s</span></div>`, html.EscapeString(geo)))
	}
	if isp != "" {
		b.WriteString(fmt.Sprintf(`<div class="v2-kv-row"><span class="v2-kv-key">ISP</span><span class="v2-kv-val">%s</span></div>`, html.EscapeString(isp)))
	}

	// Network classification
	var netFlags []string
	if s.ASN.Protected {
		netFlags = append(netFlags, `<span class="v2-pill green">protected</span>`)
	}
	if string(s.ASN.Kind) == "datacenter" {
		netFlags = append(netFlags, `<span class="v2-pill orange">datacenter</span>`)
	}
	if a.NoHardBan {
		netFlags = append(netFlags, `<span class="v2-pill green">no-ban</span>`)
	}
	if len(netFlags) > 0 {
		b.WriteString(fmt.Sprintf(`<div class="v2-kv-row"><span class="v2-kv-key">Network</span><span class="v2-kv-val">%s</span></div>`, strings.Join(netFlags, " ")))
	}

	// Score + signals
	scoreColor := "#c5cad8"
	if a.Score > 30 {
		scoreColor = "#f5a443"
	}
	if a.Score > 70 {
		scoreColor = "#f08591"
	}
	b.WriteString(fmt.Sprintf(`<div class="v2-kv-row"><span class="v2-kv-key">Local score</span><span class="v2-kv-val"><span style="font:600 14px 'JetBrains Mono',monospace;color:%s">%+d</span></span></div>`,
		scoreColor, a.Score))

	if len(a.Reasons) > 0 {
		b.WriteString(fmt.Sprintf(`<div class="v2-kv-row"><span class="v2-kv-key">Signals</span><span class="v2-kv-val" style="color:#9aa0b2;font-size:12px">%s</span></div>`,
			html.EscapeString(strings.Join(a.Reasons, " · "))))
	}

	// Provider signals
	for _, p := range s.Providers {
		scoreColor := "#c5cad8"
		if p.Score >= 90 {
			scoreColor = "#f08591"
		} else if p.Score >= 70 {
			scoreColor = "#f5a443"
		}
		label := html.EscapeString(p.Provider)
		note := ""
		if p.Note != "" {
			note = fmt.Sprintf(` <span style="color:#6b7184;font-size:11px">— %s</span>`, html.EscapeString(p.Note))
		}
		b.WriteString(fmt.Sprintf(`<div class="v2-kv-row"><span class="v2-kv-key">%s</span><span class="v2-kv-val"><span style="font:600 13px 'JetBrains Mono',monospace;color:%s">%d</span><span style="color:#6b7184;font-size:11px"> / 100</span>%s</span></div>`,
			label, scoreColor, p.Score, note))
	}

	b.WriteString(`</div></div></div>`)
	return b.String()
}

// renderV2InvestigateHistory renders the right decision history column.
func renderV2InvestigateHistory(ip string, entries []reporting.DecisionEvidence) string {
	var b strings.Builder
	count := len(entries)

	b.WriteString(fmt.Sprintf(`<div class="v2-card" style="margin-bottom:16px">
  <div class="v2-card-header">
    <span class="v2-card-title">Decision history</span>
    <span style="flex:1"></span>
    <span style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184">%d events</span>
  </div>
`, count))

	if count == 0 {
		b.WriteString(`<div class="v2-empty">No local evidence for this IP.</div>`)
	} else {
		b.WriteString(`<div class="v2-table-wrap"><table class="v2-table">
<thead><tr>
  <th>Time</th><th>Source</th><th>Score</th><th>Decision</th>
</tr></thead><tbody>`)
		for _, ev := range entries {
			statusPill, statusClass := v2EvidenceStatus(ev)
			_ = statusPill
			_ = statusClass
			b.WriteString(fmt.Sprintf(`<tr>
  <td style="color:#6b7184">%s</td>
  <td>%s</td>
  <td style="font-family:'JetBrains Mono',monospace">%d</td>
  <td><span class="v2-pill %s">%s</span></td>
</tr>`,
				html.EscapeString(ev.Timestamp.UTC().Format("01-02 15:04")),
				html.EscapeString(ev.Source),
				ev.RiskScore,
				statusClass, html.EscapeString(ev.Decision),
			))
		}
		b.WriteString(`</tbody></table></div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

func renderV2NoteForm(ip, current, csrfToken string) string {
	escaped := html.EscapeString(ip)
	escapedContent := html.EscapeString(current)
	escapedCSRF := html.EscapeString(csrfToken)
	label := "Add operator note"
	if current != "" {
		label = "Operator note"
	}
	return fmt.Sprintf(`<div class="v2-card">
  <div class="v2-card-header"><span class="v2-card-title">%s</span></div>
  <div class="v2-card-body">
    <form method="POST" action="/notes" style="display:flex;flex-direction:column;gap:10px">
      <input type="hidden" name="csrf_token" value="%s">
      <input type="hidden" name="type" value="ip">
      <input type="hidden" name="value" value="%s">
      <textarea name="content" rows="3" style="background:#0d0f14;border:1px solid #20242f;border-radius:8px;padding:10px 12px;color:#c5cad8;font:500 13px 'Hanken Grotesk',sans-serif;resize:vertical;outline:none" placeholder="Operator notes for this IP…">%s</textarea>
      <div style="display:flex;gap:8px">
        <button type="submit" style="padding:7px 16px;background:#7c6cf2;border:none;border-radius:7px;color:#fff;font:600 13px 'Hanken Grotesk',sans-serif;cursor:pointer">Save note</button>
        %s
      </div>
    </form>
  </div>
</div>`,
		label, escapedCSRF, escaped, escapedContent,
		func() string {
			if current == "" {
				return ""
			}
			return fmt.Sprintf(`<form method="POST" action="/notes/delete"><input type="hidden" name="csrf_token" value="%s"><input type="hidden" name="entity_type" value="ip"><input type="hidden" name="entity_value" value="%s"><button type="submit" style="padding:7px 14px;background:transparent;border:1px solid #20242f;border-radius:7px;color:#6b7184;font:600 13px 'Hanken Grotesk',sans-serif;cursor:pointer">Delete</button></form>`,
				escapedCSRF, escaped)
		}(),
	)
}

func v2EvidenceStatus(ev reporting.DecisionEvidence) (label, cssClass string) {
	switch {
	case ev.AbuseIPDBReported:
		return "reported", "red"
	case ev.Suppressed:
		return "suppressed", "orange"
	case ev.Decision == "report_pending":
		return "pending", "purple"
	default:
		return "ok", "green"
	}
}

// v2FormatTime formats a time for display, returning "" on zero value.
func v2FormatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05")
}
