package ui

import (
	"fmt"
	"html"
	"net/http"
	"time"

	"github.com/jm/security-automation-go/internal/adapters/nginxaccess"
)

func (s *Server) handleNginxAccessPage(w http.ResponseWriter, r *http.Request) {
	logDir := ""
	if s.cfg != nil {
		logDir = s.cfg.CrowdSec.NginxLogDir
	}

	view := buildNginxAccessView(logDir)
	renderNginxAccessPage(w, view)
}

type nginxAccessView struct {
	LogDir string
	Groups []nginxaccess.Group
	Total  int
	Error  string
	NoData bool
}

func buildNginxAccessView(logDir string) nginxAccessView {
	view := nginxAccessView{LogDir: logDir}
	if logDir == "" {
		view.Error = "Nginx log directory not configured (CrowdSec NginxLogDir)."
		return view
	}

	entries := nginxaccess.ReadDir(logDir)
	if entries == nil {
		view.NoData = true
		return view
	}
	filtered := nginxaccess.Filter4xx5xx(entries)
	if len(filtered) == 0 {
		view.NoData = true
		return view
	}
	view.Groups = nginxaccess.GroupByIP(filtered)
	view.Total = len(filtered)
	return view
}

func renderNginxAccessPage(w http.ResponseWriter, view nginxAccessView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><title>Nginx 4xx/5xx — Operator UI</title><style>`)
	fmt.Fprint(w, `body{font-family:system-ui,sans-serif;margin:0;background:#f5f7fb;color:#10243e}`)
	fmt.Fprint(w, `header{padding:1rem 1.25rem;background:#10243e;color:white}`)
	fmt.Fprint(w, `.nav{display:flex;gap:1rem;flex-wrap:wrap;margin-top:.75rem}.nav a{color:#dce8ff;text-decoration:none}`)
	fmt.Fprint(w, `main{padding:1.25rem}.panel{background:white;border:1px solid #d8e1ef;border-radius:8px;padding:1rem;margin-bottom:1rem}`)
	fmt.Fprint(w, `table{width:100%;border-collapse:collapse;font-size:.85rem}`)
	fmt.Fprint(w, `th{text-align:left;border-bottom:2px solid #d8e1ef;padding:.4rem .6rem;color:#5f6b7a;font-size:.78rem;text-transform:uppercase;letter-spacing:.04em}`)
	fmt.Fprint(w, `td{border-bottom:1px solid #eef2f8;padding:.4rem .6rem;vertical-align:top}`)
	fmt.Fprint(w, `tr:last-child td{border-bottom:0}`)
	fmt.Fprint(w, `.badge{display:inline-block;padding:.1rem .4rem;border-radius:4px;font-size:.78rem}`)
	fmt.Fprint(w, `.s4xx{background:#fff3cd;color:#856404}.s5xx{background:#f8d7da;color:#721c24}`)
	fmt.Fprint(w, `.muted{color:#5f6b7a;font-size:.82rem}.ip{font-family:monospace}`)
	fmt.Fprint(w, `.ua{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}`)
	fmt.Fprint(w, `</style></head><body>`)
	fmt.Fprint(w, `<header><strong>Operator UI</strong><div class="nav">`)
	fmt.Fprint(w, `<a href="/">Dashboard</a> <a href="/providers">Providers</a> <a href="/pipeline">Pipeline</a> <a href="/nginx-access">Nginx 4xx/5xx</a></div></header>`)
	fmt.Fprint(w, `<main>`)
	fmt.Fprintf(w, `<div class="panel"><h2>Nginx 4xx/5xx Access Log</h2>`)
	fmt.Fprintf(w, `<p class="muted">Read-only view of 4xx and 5xx HTTP responses from <code>%s</code>. Grouped by IP. Refreshes on page load. No AbuseIPDB reporting from this view.</p>`, html.EscapeString(view.LogDir))

	if view.Error != "" {
		fmt.Fprintf(w, `<p style="color:#9b1c1c">%s</p>`, html.EscapeString(view.Error))
		fmt.Fprint(w, `</div></main></body></html>`)
		return
	}
	if view.NoData {
		fmt.Fprint(w, `<p class="muted">No 4xx/5xx entries found in available log files.</p>`)
		fmt.Fprint(w, `</div></main></body></html>`)
		return
	}

	fmt.Fprintf(w, `<p class="muted">%d total error responses, %d unique IP+status combinations.</p>`, view.Total, len(view.Groups))
	fmt.Fprint(w, `</div>`)

	fmt.Fprint(w, `<div class="panel">`)
	fmt.Fprint(w, `<table><thead><tr>`)
	fmt.Fprint(w, `<th>IP</th><th>Status</th><th>Count</th><th>Method</th><th>Last URI</th><th>User-Agent</th><th>First seen</th><th>Last seen</th><th>Forensic</th>`)
	fmt.Fprint(w, `</tr></thead><tbody>`)

	for _, g := range view.Groups {
		badgeClass := "s4xx"
		if g.Status >= 500 {
			badgeClass = "s5xx"
		}
		forensicURL := fmt.Sprintf("/forensic?ip=%s", html.EscapeString(g.IP.String()))
		fmt.Fprintf(w, `<tr>`)
		fmt.Fprintf(w, `<td class="ip">%s</td>`, html.EscapeString(g.IP.String()))
		fmt.Fprintf(w, `<td><span class="badge %s">%d</span></td>`, badgeClass, g.Status)
		fmt.Fprintf(w, `<td>%d</td>`, g.Count)
		fmt.Fprintf(w, `<td>%s</td>`, html.EscapeString(g.Method))
		fmt.Fprintf(w, `<td>%s</td>`, html.EscapeString(truncate(g.LastURI, 60)))
		fmt.Fprintf(w, `<td class="ua" title="%s">%s</td>`, html.EscapeString(g.UserAgent), html.EscapeString(truncate(g.UserAgent, 40)))
		fmt.Fprintf(w, `<td class="muted">%s</td>`, formatAccessTime(g.FirstSeen))
		fmt.Fprintf(w, `<td class="muted">%s</td>`, formatAccessTime(g.LastSeen))
		fmt.Fprintf(w, `<td><a href="%s">Forensic</a></td>`, forensicURL)
		fmt.Fprint(w, `</tr>`)
	}

	fmt.Fprint(w, `</tbody></table></div>`)
	fmt.Fprint(w, `</main></body></html>`)
}

func formatAccessTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
