package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/security/audit"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

// IncidentView is the read-only view model for the Focus Incident page.
// No mutation fields — this page is investigation-only.
type IncidentView struct {
	IP            string
	Error         string
	TimelineCount int
	EventsShown   int // number of RecentEvents displayed (capped at 10)
	EvidenceCount int
	RecentEvents  []audit.TimelineEvent
	HasNote       bool
	NoteContent   string
	NoteUpdatedAt string
	// URL helpers — pre-computed so the template stays simple
	TimelineURL     string
	EvidenceURL     string
	ForensicURL     string
	CorrelatedURL   string
	AbuseIPDBURL    string
	VirusTotalURL   string
	NoteFormSnippet string // result of NoteFormHTML if no note exists yet
}

func (s *Server) buildIncidentView(ctx context.Context, ip string) IncidentView {
	view := IncidentView{
		IP:            ip,
		TimelineURL:   "/timeline?q=" + url.QueryEscape(ip),
		EvidenceURL:   "/evidence?q=" + url.QueryEscape(ip),
		ForensicURL:   "/forensic?q=" + url.QueryEscape(ip),
		CorrelatedURL: "/timeline/correlated?ip=" + url.QueryEscape(ip),
		AbuseIPDBURL:  "https://www.abuseipdb.com/check/" + url.QueryEscape(ip),
		VirusTotalURL: "https://www.virustotal.com/gui/ip-address/" + url.QueryEscape(ip),
	}

	// Timeline events for this IP
	allEvents := s.allTimelineEvents(ctx)
	for _, ev := range allEvents {
		if ev.Target == ip {
			view.TimelineCount++
			if len(view.RecentEvents) < 10 {
				view.RecentEvents = append(view.RecentEvents, ev)
			}
		}
	}
	view.EventsShown = len(view.RecentEvents)

	// Evidence count (best-effort via EvidenceSearchOptions.IP filter)
	if s.evidence != nil {
		if n, err := s.evidence.Count(ctx, reporting.EvidenceSearchOptions{IP: ip}); err == nil {
			view.EvidenceCount = n
		}
	}

	// Operator note
	if s.noteStore != nil {
		if n, ok, err := s.noteStore.Get(ctx, "ip", ip); err == nil && ok {
			view.HasNote = true
			view.NoteContent = n.Content
			view.NoteUpdatedAt = n.UpdatedAt.UTC().Format(time.RFC3339)
		}
	}
	if !view.HasNote {
		view.NoteFormSnippet = NoteFormHTML("ip", ip, "")
	}

	return view
}

func (s *Server) handleIncidentPage(w http.ResponseWriter, r *http.Request) {
	// Redirect to V2 incident page; preserve ?ip= query param.
	if ip := strings.TrimSpace(r.URL.Query().Get("ip")); ip != "" {
		http.Redirect(w, r, "/v2/incident?ip="+url.QueryEscape(ip), http.StatusMovedPermanently)
		return
	}
	http.Redirect(w, r, "/v2/incident", http.StatusMovedPermanently)
}

// IncidentPage renders the read-only Focus Incident aggregation page.
// There are NO mutation buttons on this page (no Ban, Report, Suppress, Delete).
func IncidentPage(view IncidentView) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Focus Incident — " + view.IP,
		Headline: "Focus Incident",
		Subtitle: view.IP,
		Active:   "/incident",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if view.Error != "" {
				return writeEmptyState(w, view.Error)
			}

			// Navigation panel
			if _, err := fmt.Fprintf(w,
				`<div class="panel"><h3>Investigation links</h3>`+
					`<div class="row"><span>Timeline</span><span><a href="%s">%d events</a></span></div>`+
					`<div class="row"><span>Correlated</span><span><a href="%s">By IP group</a></span></div>`+
					`<div class="row"><span>Evidence</span><span><a href="%s">%d records</a></span></div>`+
					`<div class="row"><span>Forensic</span><span><a href="%s">Deep lookup</a></span></div>`+
					`<div class="row"><span>External</span><span>`+
					`<a href="%s" rel="noopener noreferrer" target="_blank">AbuseIPDB</a> · `+
					`<a href="%s" rel="noopener noreferrer" target="_blank">VirusTotal</a>`+
					`</span></div></div>`,
				html.EscapeString(view.TimelineURL), view.TimelineCount,
				html.EscapeString(view.CorrelatedURL),
				html.EscapeString(view.EvidenceURL), view.EvidenceCount,
				html.EscapeString(view.ForensicURL),
				html.EscapeString(view.AbuseIPDBURL),
				html.EscapeString(view.VirusTotalURL),
			); err != nil {
				return err
			}

			// Recent events panel
			if len(view.RecentEvents) > 0 {
				if _, err := fmt.Fprint(w,
					`<div class="panel"><h3>Recent timeline events</h3>`+
						`<div class="table-wrap"><table><thead><tr>`+
						`<th>Timestamp</th><th>Source</th><th>Action</th><th>Result</th>`+
						`</tr></thead><tbody>`,
				); err != nil {
					return err
				}
				for _, ev := range view.RecentEvents {
					if _, err := fmt.Fprintf(w,
						`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
						html.EscapeString(ev.Timestamp),
						html.EscapeString(ev.ActorSource),
						html.EscapeString(ev.Action),
						html.EscapeString(ev.Result),
					); err != nil {
						return err
					}
				}
				if _, err := fmt.Fprintf(w,
					`</tbody></table></div>`+
						`<p><a href="%s">View all %d events →</a></p></div>`,
					html.EscapeString(view.TimelineURL), view.TimelineCount,
				); err != nil {
					return err
				}
			}

			// Operator note display or form
			if view.HasNote {
				if _, err := fmt.Fprintf(w,
					`<div class="panel"><h3>Operator note <span class="badge">local only</span></h3>`+
						`<p>%s</p><small class="muted">Updated %s</small><br>`+
						`<a href="/notes">Edit in Notes →</a></div>`,
					html.EscapeString(view.NoteContent),
					html.EscapeString(view.NoteUpdatedAt),
				); err != nil {
					return err
				}
			} else if view.NoteFormSnippet != "" {
				if _, err := fmt.Fprint(w, view.NoteFormSnippet); err != nil {
					return err
				}
			}

			return nil
		}),
	})
}
