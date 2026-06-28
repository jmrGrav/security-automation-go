package ui

import (
	"fmt"
	"html"
	"net/http"
	"net/netip"
	"strings"

	"github.com/jm/security-automation-go/internal/security/enrichment"
)

// v2IncidentEnrichment carries the enrichment data shown in the Focus Incident matrix.
// Country and ISP come from the AbuseIPDB ProviderVerdict note (via ipinfo.io).
type v2IncidentEnrichment struct {
	ASN     string // e.g. "AS15169 Google LLC" — from trusted-networks registry or enrichment
	Country string // ISO 3166-1 alpha-2 from AbuseIPDB
	ISP     string // ISP/org string from AbuseIPDB
}

func (s *Server) handleV2IncidentPage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if ip == "" {
		_, _ = fmt.Fprint(w, v2Page("Focus Incident", "/v2/incident", renderV2IncidentEmpty()))
		return
	}

	var enrich v2IncidentEnrichment
	if addr, err := netip.ParseAddr(ip); err == nil {
		if svc := s.securityIntelligenceService(); svc != nil {
			if summary, err := svc.Enrich(ctx, addr, enrichment.LookupOptions{ManualForensics: true}); err == nil {
				// ASN from trusted-networks registry (structured, best quality)
				if summary.ASN.Org != "" {
					enrich.ASN = summary.ASN.Org
					if summary.ASN.Network != "" {
						enrich.ASN += " / " + summary.ASN.Network
					}
				}
				// Country and ISP from AbuseIPDB note (backed by ipinfo.io)
				for _, v := range summary.Providers {
					if v.Provider == "abuseipdb" {
						enrich.Country = v2NoteExtract(v.Note, "country")
						enrich.ISP = v2NoteExtract(v.Note, "isp")
						break
					}
				}
			}
		}
	}

	_, _ = fmt.Fprint(w, v2Page("Focus Incident "+ip, "/v2/incident", renderV2IncidentPage(s.buildIncidentView(ctx, ip), enrich)))
}

// v2NoteExtract extracts a key=value or key="quoted value" from a gitleaks-style note string.
func v2NoteExtract(note, key string) string {
	prefix := key + "="
	idx := strings.Index(note, prefix)
	if idx < 0 {
		return ""
	}
	val := note[idx+len(prefix):]
	if strings.HasPrefix(val, `"`) {
		// Go %q quoted: isp="Google LLC"
		end := strings.Index(val[1:], `"`)
		if end < 0 {
			return ""
		}
		return val[1 : end+1]
	}
	// Unquoted (space-terminated): country=CN
	if sp := strings.IndexByte(val, ' '); sp >= 0 {
		return val[:sp]
	}
	return val
}

func renderV2IncidentEmpty() string {
	return `<div class="v2-topbar"><span class="v2-topbar-title">Focus Incident</span><span style="flex:1"></span><button class="v2-kbd-trigger" data-palette-trigger>Search IP</button></div><div class="v2-card"><div class="v2-card-body"><div class="v2-empty"><div style="font:700 16px 'Hanken Grotesk',sans-serif;color:#c5cad8;margin-bottom:5px">No investigation started.</div><div>Select an IP from Timeline, Investigation, or Notes — or press Ctrl+K.</div><div class="v2-empty-actions"><a class="v2-empty-action" href="/v2/investigate">Search IP <span>›</span></a><a class="v2-empty-action" href="/v2/timeline">Browse Timeline <span>›</span></a><a class="v2-empty-action" href="/v2/notes">Recent notes <span>›</span></a><a class="v2-empty-action" href="/v2/audit">Audit pivots <span>›</span></a></div></div></div></div>`
}

func renderV2IncidentPage(view IncidentView, enrich v2IncidentEnrichment) string {
	ip := html.EscapeString(view.IP)
	note := "No operator note yet."
	noteMeta := "local only"
	if view.HasNote {
		note = html.EscapeString(view.NoteContent)
		noteMeta = "Updated " + html.EscapeString(view.NoteUpdatedAt)
	}
	decision := "Observe"
	decisionClass := "green"
	if view.EvidenceCount > 0 || view.TimelineCount > 0 {
		decision = "Review evidence"
		decisionClass = "orange"
	}

	asnVal := `<span style="color:#4a5168;font-style:italic">enrichment not configured</span>`
	if enrich.ASN != "" {
		asnVal = html.EscapeString(enrich.ASN)
	}
	countryVal := `<span style="color:#4a5168;font-style:italic">enrichment not configured</span>`
	if enrich.Country != "" {
		countryVal = html.EscapeString(enrich.Country)
		if enrich.ISP != "" {
			countryVal += ` <span style="color:#6b7184;font:500 11px 'Hanken Grotesk',sans-serif">` + html.EscapeString(enrich.ISP) + `</span>`
		}
	}

	var eventRows strings.Builder
	if len(view.RecentEvents) == 0 {
		eventRows.WriteString(`<div class="v2-empty" style="padding:18px">No local timeline events for this IP.</div>`)
	} else {
		for _, ev := range view.RecentEvents {
			eventRows.WriteString(fmt.Sprintf(`<div style="display:grid;grid-template-columns:135px 120px 1fr;gap:10px;padding:8px 0;border-bottom:1px solid #1a1e29"><span style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184">%s</span><span class="v2-pill">%s</span><span style="font:500 12px 'Hanken Grotesk',sans-serif;color:#c5cad8">%s · %s</span></div>`,
				html.EscapeString(ev.Timestamp),
				html.EscapeString(ev.ActorSource),
				html.EscapeString(ev.Action),
				html.EscapeString(ev.Result),
			))
		}
	}

	return fmt.Sprintf(`<style>
.v2-incident-hero{display:grid;grid-template-columns:1.2fr .8fr;gap:16px;margin-bottom:16px}
.v2-incident-matrix{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.v2-incident-cell{border:1px solid #20242f;background:#10121a;border-radius:10px;padding:12px}
.v2-incident-label{font:700 10px 'JetBrains Mono',monospace;letter-spacing:.09em;text-transform:uppercase;color:#687086;margin-bottom:6px}
.v2-incident-value{font:700 15px 'Hanken Grotesk',sans-serif;color:#e8eaf1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.v2-action-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px}
.v2-action-grid a{text-decoration:none;border:1px solid #20242f;background:#10121a;border-radius:8px;padding:9px 10px;font:700 12px 'Hanken Grotesk',sans-serif;color:#c5cad8}
@media(max-width:900px){.v2-incident-hero,.v2-incident-matrix{grid-template-columns:1fr}.v2-incident-value{white-space:normal}}
</style>
<div class="v2-topbar"><span class="v2-topbar-title">Focus Incident</span><span class="v2-pill purple">%s</span><span style="flex:1"></span><button class="v2-kbd-trigger" data-palette-trigger>New search</button><span class="v2-live-badge"><span class="v2-live-dot"></span>READ ONLY</span></div>
<div class="v2-incident-hero">
  <div class="v2-card"><div class="v2-card-header"><span class="v2-card-title">Incident summary</span><span style="flex:1"></span><span class="v2-pill %s">%s</span></div><div class="v2-card-body"><div class="v2-incident-matrix">
    <div class="v2-incident-cell"><div class="v2-incident-label">IP</div><div class="v2-incident-value">%s</div></div>
    <div class="v2-incident-cell"><div class="v2-incident-label">ASN / Network</div><div class="v2-incident-value" style="font-size:13px">%s</div></div>
    <div class="v2-incident-cell"><div class="v2-incident-label">Country · ISP</div><div class="v2-incident-value" style="font-size:13px;white-space:normal">%s</div></div>
    <div class="v2-incident-cell"><div class="v2-incident-label">Provider score</div><div class="v2-incident-value">%d signals</div></div>
    <div class="v2-incident-cell"><div class="v2-incident-label">CrowdSec</div><div class="v2-incident-value">%d timeline</div></div>
    <div class="v2-incident-cell"><div class="v2-incident-label">Cloudflare</div><div class="v2-incident-value">%d evidence</div></div>
    <div class="v2-incident-cell"><div class="v2-incident-label">VirusTotal</div><div class="v2-incident-value">external</div></div>
    <div class="v2-incident-cell"><div class="v2-incident-label">AbuseIPDB</div><div class="v2-incident-value">external</div></div>
  </div></div></div>
  <div class="v2-card"><div class="v2-card-header"><span class="v2-card-title">Decision</span></div><div class="v2-card-body"><div style="font:800 28px 'Hanken Grotesk',sans-serif;color:#eef0f6;margin-bottom:8px">%s</div><div style="font:500 12px 'Hanken Grotesk',sans-serif;color:#8c94a8">Read-only focus page. Enforcement actions remain on existing explicit mutation surfaces.</div></div></div>
</div>
<div class="v2-card"><div class="v2-card-header"><span class="v2-card-title">Investigation pivots</span></div><div class="v2-card-body"><div class="v2-action-grid">
<a href="/v2/timeline?q=%s">Timeline</a><a href="/v2/timeline?q=%s">Activity</a><a href="/v2/investigate?ip=%s">Investigate</a><a href="%s" target="_blank" rel="noopener noreferrer">AbuseIPDB</a><a href="%s" target="_blank" rel="noopener noreferrer">VirusTotal</a><a href="/v2/timeline?q=%s">Related IPs</a>
</div></div></div>
<div class="v2-card"><div class="v2-card-header"><span class="v2-card-title">Timeline</span><span style="flex:1"></span><a href="/v2/timeline?q=%s" style="font:500 11px 'JetBrains Mono',monospace;color:#7c6cf2;text-decoration:none">open filtered ›</a></div><div class="v2-card-body">%s</div></div>
<div class="v2-card"><div class="v2-card-header"><span class="v2-card-title">Evidence</span><span style="flex:1"></span><span class="v2-pill">%d records</span></div><div class="v2-card-body"><a class="v2-empty-action" href="/v2/timeline?q=%s">Browse Timeline <span>›</span></a></div></div>
<div class="v2-card"><div class="v2-card-header"><span class="v2-card-title">Operator notes</span><span style="flex:1"></span><span class="v2-pill">%s</span></div><div class="v2-card-body"><p style="font:500 13px 'Hanken Grotesk',sans-serif;color:#c5cad8">%s</p><div style="margin-top:10px"><a class="v2-empty-action" href="/v2/notes">Open Notes <span>›</span></a></div></div></div>`,
		ip, decisionClass, html.EscapeString(decision),
		ip, asnVal, countryVal,
		view.TimelineCount+view.EvidenceCount, view.TimelineCount, view.EvidenceCount,
		html.EscapeString(decision),
		html.EscapeString(view.IP), html.EscapeString(view.IP), html.EscapeString(view.IP), html.EscapeString(view.AbuseIPDBURL), html.EscapeString(view.VirusTotalURL), html.EscapeString(view.IP),
		html.EscapeString(view.IP), eventRows.String(),
		view.EvidenceCount, html.EscapeString(view.IP),
		noteMeta, note,
	)
}
