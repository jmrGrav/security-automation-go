package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"time"

	"github.com/a-h/templ"
)

// buildCFSyncView reads the real enforcement state (cfBanExecutor's
// enforcement event log, plus the banlifecycle store for active-ban and
// expiration counts) rather than a periodic shadow-comparison cycle: bans
// are applied immediately per-decision in this architecture, there is no
// batch "sync cycle" to report on.
func (s *Server) buildCFSyncView(ctx context.Context) CFSyncView {
	mutationsOn := s.cfg != nil && s.cfg.Cloudflare.MutationsEnabled
	dryRun := !mutationsOn
	view := CFSyncView{MutationsOn: mutationsOn, DryRun: dryRun}

	if s.banLifecycleStore == nil && s.enforcementEventStore == nil {
		view.Wired = false
		return view
	}
	view.Wired = true

	if s.banLifecycleStore != nil {
		if active, err := s.banLifecycleStore.Active(ctx); err != nil {
			view.Error = err.Error()
		} else {
			view.ActiveBanCount = len(active)
		}
		if recent, err := s.banLifecycleStore.Recent(ctx, 500); err == nil {
			for _, e := range recent {
				if e.Status == "expired_cleaned" {
					view.ExpirationsHandled++
				}
			}
		}
	}

	if s.enforcementEventStore != nil {
		if e, ok, err := s.enforcementEventStore.LastSuccess(ctx); err == nil && ok {
			view.HasLastSuccess = true
			view.LastSuccessAt = e.OccurredAt
			view.LastSuccessIP = e.IP
			view.LastSuccessAction = e.Action
		}
		if e, ok, err := s.enforcementEventStore.LastFailure(ctx); err == nil && ok {
			view.HasLastFailure = true
			view.LastFailureAt = e.OccurredAt
			view.LastFailureIP = e.IP
			view.LastFailureError = e.Error
		}
		if events, err := s.enforcementEventStore.Recent(ctx, 50); err == nil {
			view.Events = make([]CFEnforcementEventView, 0, len(events))
			for _, e := range events {
				view.Events = append(view.Events, CFEnforcementEventView{
					OccurredAt: e.OccurredAt,
					Action:     e.Action,
					IP:         e.IP,
					Reason:     e.Reason,
					Duration:   e.Duration,
					Success:    e.Success,
					Error:      e.Error,
				})
			}
		} else if view.Error == "" {
			view.Error = err.Error()
		}
	}

	return view
}

func (s *Server) handleCFSyncPage(w http.ResponseWriter, r *http.Request) {
	view := s.buildCFSyncView(r.Context())
	_ = CFSyncPage(view).Render(r.Context(), w)
}

// CFSyncPage renders the /sync page.
func CFSyncPage(view CFSyncView) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "CF Ban Sync",
		Headline: "Cloudflare Ban Sync",
		Subtitle: "Real-time Cloudflare enforcement state: bans are applied immediately per CrowdSec/autoban decision, not on a batch cycle.",
		Active:   "/sync",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			return renderCFSyncBody(w, view)
		}),
	})
}

func renderCFSyncBody(w io.Writer, view CFSyncView) error {
	if view.Error != "" {
		_, err := fmt.Fprintf(w,
			`<div class="panel"><p class="error">Error loading enforcement data: %s</p></div>`,
			html.EscapeString(view.Error),
		)
		return err
	}

	if !view.Wired {
		_, err := fmt.Fprint(w,
			`<div class="panel"><p class="muted">Enforcement state is not available — neither the ban lifecycle store nor the enforcement event log is configured for this process.</p></div>`,
		)
		return err
	}

	modeBadge := `<span class="badge healthy">MUTATIONS ON</span>`
	if view.DryRun {
		modeBadge = `<span class="badge warning">DRY-RUN</span>`
	}

	if err := renderCFSyncSummary(w, view, modeBadge); err != nil {
		return err
	}
	if err := renderCFSyncLastActivity(w, view); err != nil {
		return err
	}
	return renderCFSyncHistory(w, view)
}

func renderCFSyncSummary(w io.Writer, view CFSyncView, modeBadge string) error {
	_, err := fmt.Fprintf(w,
		`<div class="panel"><h2>Current Cloudflare Enforcement State</h2>`+
			`<div class="badges" style="margin-bottom:.75rem">%s</div>`+
			`<div class="kv">`+
			`<div class="row"><span>Active bans</span><span>%d</span></div>`+
			`<div class="row"><span>Expirations processed</span><span>%d</span></div>`+
			`</div></div>`,
		modeBadge,
		view.ActiveBanCount,
		view.ExpirationsHandled,
	)
	return err
}

func renderCFSyncLastActivity(w io.Writer, view CFSyncView) error {
	successRow := `<div class="row"><span>Last successful CF call</span><span class="muted">None recorded yet.</span></div>`
	if view.HasLastSuccess {
		age := time.Since(view.LastSuccessAt).Truncate(time.Second)
		successRow = fmt.Sprintf(
			`<div class="row"><span>Last successful CF call</span><span>%s (%s ago) — %s %s</span></div>`,
			html.EscapeString(view.LastSuccessAt.UTC().Format(time.RFC3339)),
			html.EscapeString(age.String()),
			html.EscapeString(view.LastSuccessAction),
			html.EscapeString(view.LastSuccessIP),
		)
	}

	failureRow := `<div class="row"><span>Last failed CF call</span><span class="muted">None recorded.</span></div>`
	if view.HasLastFailure {
		age := time.Since(view.LastFailureAt).Truncate(time.Second)
		failureRow = fmt.Sprintf(
			`<div class="row"><span>Last failed CF call</span><span class="error">%s (%s ago) — %s: %s</span></div>`,
			html.EscapeString(view.LastFailureAt.UTC().Format(time.RFC3339)),
			html.EscapeString(age.String()),
			html.EscapeString(view.LastFailureIP),
			html.EscapeString(view.LastFailureError),
		)
	}

	_, err := fmt.Fprintf(w,
		`<div class="panel"><h2>Last Enforcement Activity</h2><div class="kv">%s%s</div></div>`,
		successRow, failureRow,
	)
	return err
}

func renderCFSyncHistory(w io.Writer, view CFSyncView) error {
	count := len(view.Events)
	countBadge := fmt.Sprintf(`<span class="badge">%d</span>`, count)

	if _, err := fmt.Fprintf(w,
		`<div class="panel"><h2>Recent Enforcement Events %s</h2><p class="muted">Most recent ban/deban attempts against Cloudflare, newest first.</p>`,
		countBadge,
	); err != nil {
		return err
	}

	if count == 0 {
		_, err := fmt.Fprint(w, `<p class="muted">No enforcement events recorded yet.</p></div>`)
		return err
	}

	if _, err := fmt.Fprint(w, `<table class="data-table"><thead><tr>`+
		`<th>Time</th><th>Action</th><th>IP</th><th>Reason</th><th>Duration</th><th>Result</th>`+
		`</tr></thead><tbody>`); err != nil {
		return err
	}
	for _, e := range view.Events {
		resultBadge := `<span class="badge healthy">OK</span>`
		errCell := ""
		if !e.Success {
			resultBadge = `<span class="badge error">FAILED</span>`
			errCell = fmt.Sprintf(`<div class="muted">%s</div>`, html.EscapeString(e.Error))
		}
		if _, err := fmt.Fprintf(w,
			`<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s%s</td></tr>`,
			html.EscapeString(e.OccurredAt.UTC().Format(time.RFC3339)),
			html.EscapeString(e.Action),
			html.EscapeString(e.IP),
			html.EscapeString(e.Reason),
			html.EscapeString(e.Duration.Truncate(time.Millisecond).String()),
			resultBadge,
			errCell,
		); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</tbody></table></div>`)
	return err
}
