package ui

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

func (s *Server) handleV2NotesPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var notes []sqlite.Note
	if s.noteStore != nil {
		var err error
		notes, err = s.noteStore.List(ctx)
		if err != nil {
			http.Error(w, "failed to load notes", http.StatusInternalServerError)
			return
		}
	}
	csrfToken := s.csrfTokenFromRequest(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, v2Page("Operator Notes", "/v2/notes", renderV2NotesPage(notes, csrfToken)))
}

func renderV2NotesPage(notes []sqlite.Note, csrfToken string) string {
	var sb strings.Builder
	sb.WriteString(`<style>
.v2-notes-grid{display:grid;grid-template-columns:1.2fr .8fr;gap:16px}
.v2-note-row{display:grid;grid-template-columns:90px minmax(120px,180px) 1fr auto;gap:10px;align-items:center;padding:10px 0;border-bottom:1px solid #1a1e29}
.v2-note-row:last-child{border-bottom:none}
.v2-note-content{font:500 13px 'Hanken Grotesk',sans-serif;color:#c5cad8;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.v2-note-actions{display:flex;gap:6px;flex-wrap:wrap}
.v2-note-actions a{font:600 11px 'Hanken Grotesk',sans-serif;color:#c5cad8;text-decoration:none;border:1px solid #20242f;background:#10121a;border-radius:7px;padding:5px 8px}
.v2-field{background:#0d0f14;border:1px solid #20242f;border-radius:8px;padding:9px 10px;color:#c5cad8;font:500 13px 'Hanken Grotesk',sans-serif;outline:none;width:100%}
@media(max-width:900px){.v2-notes-grid{grid-template-columns:1fr}.v2-note-row{grid-template-columns:1fr}.v2-note-actions{margin-top:2px}}
</style>`)
	sb.WriteString(`<div class="v2-topbar"><span class="v2-topbar-title">Operator Notes</span><span style="flex:1"></span><button class="v2-kbd-trigger" data-palette-trigger>Search <kbd style="background:#10121a;border:1px solid #20242f;border-radius:4px;padding:1px 6px;font:500 11px 'JetBrains Mono',monospace;color:#6b7184;margin-left:4px">Ctrl+K</kbd></button><span class="v2-live-badge"><span class="v2-live-dot"></span>LOCAL</span></div>`)
	sb.WriteString(`<div class="v2-notes-grid">`)
	// Recent notes card — show total count in header pill
	sb.WriteString(fmt.Sprintf(`<div class="v2-card"><div class="v2-card-header"><span class="v2-card-title">Recent notes</span><span style="flex:1"></span><span class="v2-pill">%d notes</span><span class="v2-pill">Search</span><span class="v2-pill">Filters</span></div><div class="v2-card-body">`, len(notes)))
	if len(notes) == 0 {
		sb.WriteString(`<div class="v2-empty"><div style="font:700 16px 'Hanken Grotesk',sans-serif;color:#c5cad8;margin-bottom:5px">No notes.</div><div>Annotations will appear here without affecting provider decisions.</div><div style="margin-top:8px;font:500 12px 'Hanken Grotesk',sans-serif;color:#5a6072">Notes can tag IPs, ASNs, domains, or evidence IDs. Use the quick-create form →</div><div class="v2-empty-actions"><a class="v2-empty-action" href="/v2/investigate">Open Focus Incident <span>›</span></a><a class="v2-empty-action" href="/v2/timeline">Browse Timeline <span>›</span></a><a class="v2-empty-action" href="/v2/audit">Recent activity <span>›</span></a></div></div>`)
	} else {
		display := notes
		if len(display) > 6 {
			display = display[:6]
		}
		for _, note := range display {
			entity := note.EntityValue
			q := url.QueryEscape(entity)
			incidentHref := "/v2/timeline?q=" + q
			if note.EntityType == "ip" {
				incidentHref = "/v2/incident?ip=" + q
			}
			sb.WriteString(fmt.Sprintf(`<div class="v2-note-row"><span class="v2-pill">%s</span><a href="%s" style="font:700 12px 'JetBrains Mono',monospace;color:#9b8cff;text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">%s</a><span class="v2-note-content">%s</span><span class="v2-note-actions"><a href="%s">Focus</a><a href="/v2/timeline?q=%s">Timeline</a><a href="/v2/investigate?q=%s">Investigate</a></span></div>`,
				html.EscapeString(note.EntityType),
				html.EscapeString(incidentHref),
				html.EscapeString(entity),
				html.EscapeString(note.Content),
				html.EscapeString(incidentHref),
				q,
				q,
			))
		}
		if len(notes) > 6 {
			sb.WriteString(fmt.Sprintf(`<a href="/notes" style="display:block;text-align:center;font:600 11px 'Hanken Grotesk',sans-serif;color:#9b8cff;text-decoration:none;padding:8px;border-top:1px solid #1a1e29">View all %d notes</a>`, len(notes)))
		}
	}
	sb.WriteString(`</div></div>`)
	sb.WriteString(`<div style="display:flex;flex-direction:column;gap:16px">`)

	// Quick create form
	sb.WriteString(`<div class="v2-card"><div class="v2-card-header"><span class="v2-card-title">Quick create</span></div><div class="v2-card-body"><form method="post" action="/notes" style="display:grid;gap:9px"><input type="hidden" name="csrf_token" value="` + html.EscapeString(csrfToken) + `"><select class="v2-field" name="type" style="width:auto;cursor:pointer"><option value="ip">IP address</option><option value="asn">ASN</option><option value="domain">Domain</option><option value="other">Other</option></select><input class="v2-field" name="value" placeholder="IP, ASN, provider, evidence id"><textarea class="v2-field" name="content" rows="4" placeholder="Operator note..."></textarea><button type="submit" style="padding:8px 12px;background:#7c6cf2;border:none;border-radius:8px;color:#fff;font:700 12px 'Hanken Grotesk',sans-serif;cursor:pointer">Save note</button><p style="font:500 11px 'JetBrains Mono',monospace;color:#5a6072;margin-top:6px">Ctrl+K to search existing notes</p></form></div></div>`)

	// Pinned entities — group by type
	sb.WriteString(`<div class="v2-card"><div class="v2-card-header"><span class="v2-card-title">Pinned entities</span></div><div class="v2-card-body" style="padding:10px 18px">`)
	if len(notes) == 0 {
		sb.WriteString(`<div style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184;padding:6px 0">Annotate an IP, ASN, or domain to pin it here.</div>`)
	} else {
		byType := map[string][]sqlite.Note{}
		for _, n := range notes {
			byType[n.EntityType] = append(byType[n.EntityType], n)
		}
		for _, typ := range []string{"ip", "asn", "domain", "other"} {
			group := byType[typ]
			if len(group) == 0 {
				continue
			}
			sb.WriteString(fmt.Sprintf(`<div style="font:700 9px 'Hanken Grotesk',sans-serif;color:#7b8196;letter-spacing:.06em;text-transform:uppercase;margin-bottom:5px;margin-top:10px">%s</div>`, html.EscapeString(typ)))
			limit := len(group)
			if limit > 4 {
				limit = 4
			}
			sb.WriteString(`<div class="v2-chip-row">`)
			for _, n := range group[:limit] {
				investHref := "/v2/investigate?ip=" + url.QueryEscape(n.EntityValue)
				if typ != "ip" {
					investHref = "/v2/timeline?q=" + url.QueryEscape(n.EntityValue)
				}
				sb.WriteString(fmt.Sprintf(`<a href="%s" class="v2-chip ok" style="text-decoration:none">%s</a>`, html.EscapeString(investHref), html.EscapeString(n.EntityValue)))
			}
			sb.WriteString(`</div>`)
		}
	}
	sb.WriteString(`</div></div>`)

	// Recent investigations shortcut panel
	sb.WriteString(`<div class="v2-card"><div class="v2-card-header"><span class="v2-card-title">Recent investigations</span></div><div class="v2-card-body" style="padding:10px 18px"><div class="v2-kv">`)
	ipNotes := []sqlite.Note{}
	for _, n := range notes {
		if n.EntityType == "ip" {
			ipNotes = append(ipNotes, n)
		}
	}
	if len(ipNotes) == 0 {
		sb.WriteString(`<div style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184;padding:6px 0">Annotated IPs appear here for quick re-investigation.</div>`)
	} else {
		limit := len(ipNotes)
		if limit > 5 {
			limit = 5
		}
		for _, n := range ipNotes[:limit] {
			sb.WriteString(fmt.Sprintf(`<div class="v2-kv-row"><a href="/v2/investigate?ip=%s" style="color:#7c6cf2;text-decoration:none;font:600 12px 'JetBrains Mono',monospace;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">%s</a></div>`,
				url.QueryEscape(n.EntityValue), html.EscapeString(n.EntityValue)))
		}
	}
	sb.WriteString(`</div></div></div>`)

	// Suggested annotations — always visible, guides operators
	sb.WriteString(`<div class="v2-card"><div class="v2-card-header"><span class="v2-card-title">Suggested annotations</span></div><div class="v2-card-body" style="padding:10px 18px"><div class="v2-kv">`)
	sb.WriteString(`<div class="v2-kv-row"><a href="/v2/timeline?q=ban" style="color:#9aa0b2;text-decoration:none;font:500 12px 'Hanken Grotesk',sans-serif">Annotate recent bans →</a></div>`)
	sb.WriteString(`<div class="v2-kv-row"><a href="/v2/investigate" style="color:#9aa0b2;text-decoration:none;font:500 12px 'Hanken Grotesk',sans-serif">Investigate top attacker →</a></div>`)
	sb.WriteString(`<div class="v2-kv-row"><a href="/v2/cloudflare" style="color:#9aa0b2;text-decoration:none;font:500 12px 'Hanken Grotesk',sans-serif">Review CF boundary →</a></div>`)
	sb.WriteString(`</div></div></div>`)

	sb.WriteString(`</div></div>`) // end right column + grid
	return sb.String()
}
