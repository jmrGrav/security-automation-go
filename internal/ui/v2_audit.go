package ui

import (
	"fmt"
	"html"
	"net/http"
	"strings"
)

func (s *Server) handleV2AuditTrailPage(w http.ResponseWriter, r *http.Request) {
	_, cancel := stableUIReadContext(r.Context())
	defer cancel()
	view := s.auditTrailView(r.URL.Query().Get("q"), "/v2/audit")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, v2Page("Audit", "/v2/audit", renderV2AuditTrailPage(view, s.csrfTokenFromRequest(r))))
}

func renderV2AuditTrailPage(view AuditTrailView, csrfToken string) string {
	var sb strings.Builder
	sb.WriteString(`<style>
.v2-audit-row{display:grid;grid-template-columns:150px 130px 1fr 150px 120px;gap:10px;align-items:center;padding:9px 0;border-bottom:1px solid #1a1e29}
.v2-audit-row:last-child{border-bottom:none}
.v2-audit-row span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
@media(max-width:900px){.v2-audit-row{grid-template-columns:1fr}.v2-audit-row span{white-space:normal}}
</style>`)
	sb.WriteString(fmt.Sprintf(`<div class="v2-topbar"><span class="v2-topbar-title">Audit</span><span style="flex:1"></span><form method="get" action="/v2/audit" style="display:flex;gap:8px;min-width:min(420px,100%%)"><input name="q" value="%s" placeholder="action, target, result..." style="flex:1;background:#10121a;border:1px solid #20242f;border-radius:8px;padding:8px 10px;color:#c5cad8;font:500 12px 'JetBrains Mono',monospace"><button type="submit" style="background:#1a1e29;border:1px solid #2a2f42;border-radius:8px;color:#c5cad8;padding:7px 10px;font:700 12px 'Hanken Grotesk',sans-serif">Search</button></form><span class="v2-live-badge"><span class="v2-live-dot"></span>APPEND ONLY</span></div>`, html.EscapeString(view.Query)))
	sb.WriteString(`<div class="v2-card" data-live-shell="audit" data-live-refresh-url="` + html.EscapeString(view.RefreshURL) + `" data-live-refresh-interval="10000"><div class="v2-card-header"><span class="v2-card-title">Recent activity</span><span style="flex:1"></span><span class="v2-pill">redacted</span></div><div class="v2-card-body">`)
	if len(view.Entries) == 0 {
		sb.WriteString(`<div class="v2-empty"><div style="font:700 16px 'Hanken Grotesk',sans-serif;color:#c5cad8;margin-bottom:5px">No audit events yet.</div><div>UI lookups and operator actions will appear here when recorded.</div><div class="v2-empty-actions"><a class="v2-empty-action" href="/v2/timeline">Suggested actions <span>Timeline</span></a><a class="v2-empty-action" href="/v2/providers">Quick links <span>Providers</span></a><a class="v2-empty-action" href="/v2/health">Health <span>Open</span></a><a class="v2-empty-action" href="/v2/investigate">Recent searches <span>Search IP</span></a></div></div>`)
	} else {
		sb.WriteString(`<div class="v2-audit-row" style="font:700 10px 'JetBrains Mono',monospace;letter-spacing:.08em;text-transform:uppercase;color:#687086"><span>timestamp</span><span>actor/source</span><span>action</span><span>target</span><span>result</span></div>`)
		for _, entry := range view.Entries {
			sb.WriteString(fmt.Sprintf(`<div class="v2-audit-row"><span style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184">%s</span><span class="v2-pill">%s</span><span style="font:700 12px 'Hanken Grotesk',sans-serif;color:#e8eaf1">%s</span><span style="font:500 12px 'JetBrains Mono',monospace;color:#9b8cff">%s</span><span class="v2-pill">%s</span></div>`,
				html.EscapeString(valueOrUnknown(entry.Timestamp)),
				html.EscapeString(auditActorSource(entry)),
				html.EscapeString(valueOrUnknown(entry.Action)),
				html.EscapeString(auditDisplayValue(entry.Target)),
				html.EscapeString(auditDisplayValue(entry.Result)),
			))
		}
	}
	sb.WriteString(`</div></div>`)
	_ = csrfToken
	return sb.String()
}
