package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/security/audit"
)

// CorrelatedGroup holds events for a single IP grouped from allTimelineEvents.
type CorrelatedGroup struct {
	Key        string // IP address (Target field)
	EventCount int
	FirstSeen  time.Time
	LastSeen   time.Time
	Sources    []string // distinct ActorSource names
	Events     []audit.TimelineEvent
}

// CorrelatedTimelineView is the view model for the correlated timeline page.
type CorrelatedTimelineView struct {
	Groups   []CorrelatedGroup
	FilterIP string
	Total    int // total number of groups
}

// groupTimelineByIP groups events by their Target field (IP address).
// If filterIP is non-empty, only events matching that IP are included.
// Returns groups sorted by LastSeen descending (most recent activity first).
func groupTimelineByIP(events []audit.TimelineEvent, filterIP string) []CorrelatedGroup {
	m := make(map[string]*CorrelatedGroup)
	for i := range events {
		ev := events[i]
		key := strings.TrimSpace(ev.Target)
		if key == "" {
			continue
		}
		if filterIP != "" && key != filterIP {
			continue
		}
		g, ok := m[key]
		if !ok {
			g = &CorrelatedGroup{Key: key}
			m[key] = g
		}
		g.Events = append(g.Events, ev)
		g.EventCount++

		// Parse timestamp string (RFC3339Nano) for time comparisons.
		ts, _ := time.Parse(time.RFC3339Nano, ev.Timestamp)
		if !ts.IsZero() {
			if g.FirstSeen.IsZero() || ts.Before(g.FirstSeen) {
				g.FirstSeen = ts
			}
			if ts.After(g.LastSeen) {
				g.LastSeen = ts
			}
		}

		// Track distinct sources via ActorSource.
		found := false
		for _, s := range g.Sources {
			if s == ev.ActorSource {
				found = true
				break
			}
		}
		if !found && ev.ActorSource != "" {
			g.Sources = append(g.Sources, ev.ActorSource)
		}
	}

	out := make([]CorrelatedGroup, 0, len(m))
	for _, g := range m {
		out = append(out, *g)
	}
	// Sort by LastSeen descending (most recent activity first).
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

// handleCorrelatedTimelinePage serves GET /timeline/correlated.
func (s *Server) handleCorrelatedTimelinePage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()
	filterIP := strings.TrimSpace(r.URL.Query().Get("ip"))
	events := s.allTimelineEvents(ctx)
	groups := groupTimelineByIP(events, filterIP)
	view := CorrelatedTimelineView{
		Groups:   groups,
		FilterIP: filterIP,
		Total:    len(groups),
	}
	_ = CorrelatedTimelinePage(view).Render(ctx, w)
}

// CorrelatedTimelinePage renders the correlated timeline view.
func CorrelatedTimelinePage(view CorrelatedTimelineView) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Correlated Timeline",
		Headline: "Correlated Timeline",
		Subtitle: "Events grouped by IP across all sources.",
		Active:   "/timeline/correlated",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			// Filter form
			if _, err := fmt.Fprintf(w,
				`<div class="panel"><form method="GET" action="/timeline/correlated">`+
					`<label for="ct-ip">Filter by IP</label> `+
					`<input id="ct-ip" type="search" name="ip" value="%s" placeholder="e.g. 1.2.3.4"> `+
					`<button type="submit">Apply</button>`+
					`</form></div>`,
				html.EscapeString(view.FilterIP),
			); err != nil {
				return err
			}
			if len(view.Groups) == 0 {
				return writeEmptyState(w, "No correlated events found.")
			}
			// Summary line
			if _, err := fmt.Fprintf(w,
				`<p class="muted">%d IP group(s) found.</p>`, view.Total,
			); err != nil {
				return err
			}
			// Group cards
			for _, g := range view.Groups {
				sources := html.EscapeString(strings.Join(g.Sources, ", "))
				firstSeen := ""
				if !g.FirstSeen.IsZero() {
					firstSeen = g.FirstSeen.UTC().Format(time.RFC3339)
				}
				lastSeen := ""
				if !g.LastSeen.IsZero() {
					lastSeen = g.LastSeen.UTC().Format(time.RFC3339)
				}
				ip := html.EscapeString(g.Key)
				if _, err := fmt.Fprintf(w,
					`<div class="panel"><h3>%s <span class="badge">%d events</span></h3>`+
						`<div class="row"><span>Sources</span><span>%s</span></div>`+
						`<div class="row"><span>First seen</span><span>%s</span></div>`+
						`<div class="row"><span>Last seen</span><span>%s</span></div>`+
						`<div class="row"><span>Links</span><span>`+
						`<a href="/timeline?q=%s">Timeline</a> · `+
						`<a href="/forensic?q=%s">Forensic</a> · `+
						`<a href="/incident?ip=%s">Focus Incident</a>`+
						`</span></div></div>`,
					ip, g.EventCount, sources, firstSeen, lastSeen,
					ip, ip, ip,
				); err != nil {
					return err
				}
			}
			return nil
		}),
	})
}
