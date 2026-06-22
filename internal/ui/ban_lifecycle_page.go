package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"sort"

	"github.com/a-h/templ"
)

func (s *Server) handleBanLifecyclePage(w http.ResponseWriter, r *http.Request) {
	eventID := newUIEventID()
	s.audit.Record("ban_lifecycle_view", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         "ban-lifecycle",
		"result":         "read-only",
		"correlation_id": eventID,
		"event_id":       eventID,
	})
	_ = BanLifecyclePage(s.banLifecycleView(r.Context())).Render(r.Context(), w)
}

func BanLifecyclePage(view BanLifecycleView) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Cloudflare Ban Lifecycle",
		Headline: "Cloudflare Ban Lifecycle",
		Subtitle: "Full history of local autoban lifecycle entries — active, expired, auto-debanned, and manually overridden — with recidive-aware durations. Managed bans only — manual Cloudflare rules are never shown or touched here.",
		Active:   "/ban-lifecycle",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if !view.Wired {
				return writeEmptyState(w, "Ban lifecycle store is not wired into this process.")
			}
			if view.Error != "" {
				if _, err := fmt.Fprintf(w, `<div class="panel"><p class="error">%s</p></div>`, html.EscapeString(view.Error)); err != nil {
					return err
				}
			}
			if len(view.Entries) == 0 {
				return writeEmptyState(w, "No managed Cloudflare ban lifecycle entries yet.")
			}
			if _, err := fmt.Fprint(w, `<div style="overflow-x:auto"><table><thead><tr><th>IP</th><th>Source</th><th>Reason</th><th>Confidence</th><th>Recidive</th><th>Created</th><th>Expires</th><th>Duration</th><th>Rule ID</th><th>Status</th></tr></thead><tbody>`); err != nil {
				return err
			}
			for _, entry := range view.Entries {
				if err := renderBanLifecycleRow(w, entry); err != nil {
					return err
				}
			}
			_, err := fmt.Fprint(w, `</tbody></table></div>`)
			return err
		}),
	})
}

func (s *Server) banLifecycleView(ctx context.Context) BanLifecycleView {
	if s.banLifecycleStore == nil {
		return BanLifecycleView{Wired: false}
	}
	entries, err := s.banLifecycleStore.Recent(ctx, 200)
	if err != nil {
		return BanLifecycleView{Wired: true, Error: err.Error()}
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].CreatedAt.After(entries[j].CreatedAt)
	})
	views := make([]BanLifecycleEntryView, 0, len(entries))
	for _, e := range entries {
		views = append(views, BanLifecycleEntryView{
			IP:            e.IP,
			Source:        valueOrFallback(e.Source, "unknown"),
			Reason:        valueOrFallback(e.Reason, "unspecified"),
			Confidence:    e.Confidence,
			CreatedAt:     e.CreatedAt.UTC().Format("2006-01-02 15:04:05Z"),
			ExpiresAt:     e.ExpiresAt.UTC().Format("2006-01-02 15:04:05Z"),
			Duration:      e.Duration.String(),
			RuleID:        valueOrFallback(e.RuleID, "n/a"),
			RecidiveLevel: e.RecidiveLevel,
			Status:        valueOrFallback(e.Status, "active"),
		})
	}
	return BanLifecycleView{Wired: true, Entries: views}
}

func renderBanLifecycleRow(w io.Writer, entry BanLifecycleEntryView) error {
	recidiveBadge := `<span class="badge">1st</span>`
	switch {
	case entry.RecidiveLevel == 2:
		recidiveBadge = `<span class="badge warning">2nd</span>`
	case entry.RecidiveLevel >= 3:
		recidiveBadge = `<span class="badge error">3rd+</span>`
	}
	statusClass := "badge"
	switch entry.Status {
	case "active":
		statusClass = "badge warning"
	case "auto_debanned":
		statusClass = "badge success"
	case "manual_override":
		statusClass = "badge error"
	}
	_, err := fmt.Fprintf(w,
		`<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><span class="%s">%s</span></td></tr>`,
		html.EscapeString(entry.IP),
		html.EscapeString(entry.Source),
		html.EscapeString(entry.Reason),
		entry.Confidence,
		recidiveBadge,
		html.EscapeString(entry.CreatedAt),
		html.EscapeString(entry.ExpiresAt),
		html.EscapeString(entry.Duration),
		html.EscapeString(entry.RuleID),
		statusClass,
		html.EscapeString(entry.Status),
	)
	return err
}
