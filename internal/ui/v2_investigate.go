package ui

import (
	"fmt"
	"html"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/security/enrichment"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

// handleV2Investigate serves GET /v2/investigate.
// Without ?q= : shows recent evidence as a live feed.
// With ?q=<ip>: shows enrichment card + evidence for that IP.
func (s *Server) handleV2Investigate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// No query → show recent feed
	if q == "" {
		var recentEntries []reporting.DecisionEvidence
		if s.evidence != nil {
			recentEntries, _ = s.evidence.Search(ctx, reporting.EvidenceSearchOptions{Limit: 30})
		}
		_, _ = fmt.Fprint(w, v2Page("Investigate", "/v2/investigate", renderV2InvestigateEmpty(recentEntries)))
		return
	}

	// Try to parse as IP
	ip, err := netip.ParseAddr(q)
	if err != nil || !ip.IsValid() {
		// Not an IP → show error inline, keep feed
		var recentEntries []reporting.DecisionEvidence
		if s.evidence != nil {
			recentEntries, _ = s.evidence.Search(ctx, reporting.EvidenceSearchOptions{Limit: 30})
		}
		content := renderV2InvestigateInvalidIP(q) + renderV2InvestigateEmpty(recentEntries)
		_, _ = fmt.Fprint(w, v2Page("Investigate", "/v2/investigate", content))
		return
	}

	// Valid IP → build full view
	view := ForensicView{IP: q}

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
		ipEvidence, _ = s.evidence.Search(ctx, reporting.EvidenceSearchOptions{IP: q, Limit: 50})
	}

	var noteContent string
	if s.noteStore != nil {
		existing, _, _ := s.noteStore.Get(ctx, "ip", q)
		noteContent = existing.Content
	}

	s.audit.Record("forensic_lookup", map[string]string{"ip": q, "source": "ui_v2"})

	_, _ = fmt.Fprint(w, v2Page("Investigate · "+html.EscapeString(q), "/v2/investigate",
		renderV2InvestigateIP(view, ipEvidence, noteContent, s.csrfTokenFromRequest(r))))
}

// renderV2InvestigateEmpty renders the "no search" state with a recent evidence feed.
func renderV2InvestigateEmpty(recent []reporting.DecisionEvidence) string {
	var b strings.Builder

	b.WriteString(`
<div class="v2-topbar">
  <span class="v2-topbar-title">Investigate</span>
  <span style="flex:1"></span>
  <button class="v2-kbd-trigger" data-palette-trigger style="background:none;border:1px solid #2a2f42;padding:5px 12px;border-radius:7px;cursor:pointer">
    <span style="font-size:13px">⊕</span>
    <span>Search IP</span>
    <kbd style="background:#10121a;border:1px solid #20242f;border-radius:4px;padding:1px 6px;font:500 11px 'JetBrains Mono',monospace;color:#6b7184;margin-left:4px">Ctrl+K</kbd>
  </button>
  <span class="v2-live-badge"><span class="v2-live-dot"></span>LIVE</span>
</div>
`)

	b.WriteString(`<div class="v2-card">
  <div class="v2-card-header">
    <span class="v2-card-title">Recent evidence</span>
    <span style="flex:1"></span>
    <span style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184">last 30 events · click IP to investigate</span>
  </div>
`)

	if len(recent) == 0 {
		b.WriteString(`<div class="v2-empty">No evidence recorded yet.</div>`)
	} else {
		b.WriteString(`<div class="v2-table-wrap"><table class="v2-table">
<thead><tr>
  <th>timestamp</th><th>IP</th><th>source</th><th>type</th><th>score</th><th>decision</th><th>status</th>
</tr></thead><tbody>`)
		for _, ev := range recent {
			statusPill, statusClass := v2EvidenceStatus(ev)
			b.WriteString(fmt.Sprintf(`<tr>
  <td>%s</td>
  <td><a href="/v2/investigate?q=%s">%s</a></td>
  <td>%s</td>
  <td>%s</td>
  <td>%d</td>
  <td>%s</td>
  <td><span class="v2-pill %s">%s</span></td>
</tr>`,
				html.EscapeString(ev.Timestamp.Format("2006-01-02 15:04:05")),
				url.QueryEscape(ev.IP), html.EscapeString(ev.IP),
				html.EscapeString(ev.Source),
				html.EscapeString(ev.AbuseType),
				ev.RiskScore,
				html.EscapeString(ev.Decision),
				statusClass, statusPill,
			))
		}
		b.WriteString(`</tbody></table></div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

func renderV2InvestigateInvalidIP(q string) string {
	return fmt.Sprintf(`<div style="margin-bottom:14px;padding:10px 14px;border:1px solid rgba(239,95,107,.24);border-radius:8px;background:rgba(239,95,107,.08);font:500 13px 'JetBrains Mono',monospace;color:#f08591">Not a valid IP address: %s</div>`,
		html.EscapeString(q))
}

// renderV2InvestigateIP renders the full investigate view for a known IP.
func renderV2InvestigateIP(view ForensicView, ipEvidence []reporting.DecisionEvidence, noteContent, csrfToken string) string {
	var b strings.Builder
	ip := html.EscapeString(view.IP)

	// Topbar
	b.WriteString(fmt.Sprintf(`
<div class="v2-topbar">
  <span class="v2-topbar-title">Investigate</span>
  <span style="display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:6px;background:#1a1e29;border:1px solid #2a2f42;font:600 13px 'JetBrains Mono',monospace;color:#c5cad8">%s</span>
  <span style="flex:1"></span>
  <a href="/v2/investigate" style="font:500 12px 'Hanken Grotesk',sans-serif;color:#6b7184;text-decoration:none;padding:4px 10px;border:1px solid #20242f;border-radius:6px">← Clear</a>
  <button class="v2-kbd-trigger" data-palette-trigger style="background:none;border:1px solid #2a2f42;padding:5px 12px;border-radius:7px;cursor:pointer">
    <span style="font-size:13px">⊕</span><span>New search</span>
    <kbd style="background:#10121a;border:1px solid #20242f;border-radius:4px;padding:1px 6px;font:500 11px 'JetBrains Mono',monospace;color:#6b7184;margin-left:4px">Ctrl+K</kbd>
  </button>
  <span class="v2-live-badge"><span class="v2-live-dot"></span>LIVE</span>
</div>
`, ip))

	// Error state
	if view.Error != "" {
		b.WriteString(fmt.Sprintf(`<div style="margin-bottom:14px;padding:10px 14px;border:1px solid rgba(239,95,107,.24);border-radius:8px;background:rgba(239,95,107,.08);font:500 13px 'JetBrains Mono',monospace;color:#f08591">%s</div>`,
			html.EscapeString(view.Error)))
	}

	// Quick links row
	b.WriteString(fmt.Sprintf(`
<div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">
  <a href="/timeline?q=%s" class="v2-pill purple">⟳ Timeline</a>
  <a href="/incident?ip=%s" class="v2-pill purple">◎ Focus Incident</a>
  <a href="https://www.abuseipdb.com/check/%s" target="_blank" rel="noopener" class="v2-pill">AbuseIPDB ↗</a>
  <a href="https://www.virustotal.com/gui/ip-address/%s" target="_blank" rel="noopener" class="v2-pill">VirusTotal ↗</a>
</div>
`, url.QueryEscape(view.IP), url.QueryEscape(view.IP), url.QueryEscape(view.IP), url.QueryEscape(view.IP)))

	// Enrichment card
	if view.HasEnrichment {
		b.WriteString(renderV2EnrichmentCard(view))
	} else if view.EnrichmentError != "" {
		b.WriteString(fmt.Sprintf(`<div class="v2-card" style="margin-bottom:16px"><div class="v2-card-body"><span style="color:#6b7184;font:500 12px 'JetBrains Mono',monospace">%s</span></div></div>`,
			html.EscapeString(view.EnrichmentError)))
	}

	// Evidence card
	b.WriteString(renderV2EvidenceCard(view.IP, ipEvidence))

	// Operator note
	if csrfToken != "" {
		b.WriteString(renderV2NoteForm(view.IP, noteContent, csrfToken))
	}

	return b.String()
}

func renderV2EnrichmentCard(view ForensicView) string {
	var b strings.Builder
	s := view.Summary
	a := view.Assess

	// Header badges
	var headerPills strings.Builder
	if s.CacheHit {
		headerPills.WriteString(`<span class="v2-pill orange">cache hit</span> `)
	} else {
		headerPills.WriteString(`<span class="v2-pill green">fresh</span> `)
	}
	if a.NoHardBan {
		headerPills.WriteString(`<span class="v2-pill green">protected network</span> `)
	}
	if a.HardBanAllowed {
		headerPills.WriteString(`<span class="v2-pill red">hard ban allowed</span> `)
	}

	b.WriteString(fmt.Sprintf(`<div class="v2-card" style="margin-bottom:16px">
  <div class="v2-card-header">
    <span class="v2-card-title">IP Enrichment</span>
    <span style="flex:1"></span>
    %s
  </div>
  <div class="v2-card-body">
    <div class="v2-kv">
`, headerPills.String()))

	// Score delta
	b.WriteString(fmt.Sprintf(`<div class="v2-kv-row"><span class="v2-kv-key">score delta</span><span class="v2-kv-val"><span style="font:600 14px 'JetBrains Mono',monospace;color:%s">%+d</span></span></div>`,
		func() string {
			if a.Score > 30 {
				return "#f5a443"
			}
			return "#c5cad8"
		}(), a.Score))

	if len(a.Reasons) > 0 {
		b.WriteString(fmt.Sprintf(`<div class="v2-kv-row"><span class="v2-kv-key">signals</span><span class="v2-kv-val" style="color:#9aa0b2;font-size:12px">%s</span></div>`,
			html.EscapeString(strings.Join(a.Reasons, " · "))))
	}

	// DNS
	dnsVal := `<span style="color:#4a5168">no PTR</span>`
	if s.DNS.Hostname != "" {
		dnsVal = html.EscapeString(s.DNS.Hostname)
		if s.DNS.Confirmed {
			dnsVal += ` <span class="v2-pill green">confirmed</span>`
		} else {
			dnsVal += ` <span class="v2-pill orange">rDNS unconfirmed</span>`
		}
		if s.DNS.TrustedBot {
			dnsVal += ` <span class="v2-pill green">trusted bot</span>`
		}
	}
	b.WriteString(fmt.Sprintf(`<div class="v2-kv-row"><span class="v2-kv-key">DNS / rDNS</span><span class="v2-kv-val">%s</span></div>`, dnsVal))

	// ASN
	asnVal := `<span style="color:#4a5168">not configured</span>`
	if s.ASN.Org != "" {
		asnVal = html.EscapeString(s.ASN.Org)
		if s.ASN.Network != "" {
			asnVal += fmt.Sprintf(` <span style="color:#6b7184">(%s)</span>`, html.EscapeString(s.ASN.Network))
		}
		switch {
		case s.ASN.Protected:
			asnVal += ` <span class="v2-pill green">protected</span>`
		case string(s.ASN.Kind) == "datacenter":
			asnVal += ` <span class="v2-pill orange">datacenter</span>`
		}
	}
	b.WriteString(fmt.Sprintf(`<div class="v2-kv-row"><span class="v2-kv-key">ASN / network</span><span class="v2-kv-val">%s</span></div>`, asnVal))

	// Provider scores
	for _, p := range s.Providers {
		scoreColor := "#c5cad8"
		if p.Score >= 90 {
			scoreColor = "#f08591"
		} else if p.Score >= 70 {
			scoreColor = "#f5a443"
		}
		label := html.EscapeString(p.Provider)
		if p.Manual {
			label += ` <span class="v2-pill">manual</span>`
		}
		note := ""
		if p.Note != "" {
			note = fmt.Sprintf(` <span style="color:#6b7184">— %s</span>`, html.EscapeString(p.Note))
		}
		b.WriteString(fmt.Sprintf(`<div class="v2-kv-row"><span class="v2-kv-key">%s</span><span class="v2-kv-val"><span style="font:600 13px 'JetBrains Mono',monospace;color:%s">%d</span><span style="color:#6b7184;font-size:11px"> / 100</span>%s</span></div>`,
			label, scoreColor, p.Score, note))
	}

	b.WriteString(`    </div>
  </div>
</div>`)
	return b.String()
}

func renderV2EvidenceCard(ip string, entries []reporting.DecisionEvidence) string {
	var b strings.Builder
	count := len(entries)

	b.WriteString(fmt.Sprintf(`<div class="v2-card" style="margin-bottom:16px">
  <div class="v2-card-header">
    <span class="v2-card-title">Local Evidence</span>
    <span style="flex:1"></span>
    <span style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184">%d events for %s</span>
  </div>
`, count, html.EscapeString(ip)))

	if count == 0 {
		b.WriteString(`<div class="v2-empty">No local evidence for this IP.</div>`)
	} else {
		b.WriteString(`<div class="v2-table-wrap"><table class="v2-table">
<thead><tr>
  <th>timestamp</th><th>source</th><th>type</th><th>score</th><th>confidence</th><th>decision</th><th>status</th>
</tr></thead><tbody>`)
		for _, ev := range entries {
			statusPill, statusClass := v2EvidenceStatus(ev)
			b.WriteString(fmt.Sprintf(`<tr>
  <td>%s</td>
  <td>%s</td>
  <td>%s</td>
  <td>%d</td>
  <td>%.2f</td>
  <td>%s</td>
  <td><span class="v2-pill %s">%s</span></td>
</tr>`,
				html.EscapeString(ev.Timestamp.Format("2006-01-02 15:04:05")),
				html.EscapeString(ev.Source),
				html.EscapeString(ev.AbuseType),
				ev.RiskScore,
				ev.Confidence,
				html.EscapeString(ev.Decision),
				statusClass, statusPill,
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
      <input type="hidden" name="entity_type" value="ip">
      <input type="hidden" name="entity_value" value="%s">
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
