package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"sort"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
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
	_ = BanLifecyclePage(s.banLifecycleView(r.Context()), s.banDebanActionsAvailable(), s.csrfTokenFromRequest(r)).Render(r.Context(), w)
}

// banDebanActionsAvailable reports whether the deban/clear actions can be
// offered at all: a BanDebanner must be wired and Cloudflare mutations must
// be enabled. This mirrors the checks the handlers themselves enforce, so
// the UI never shows a button that would immediately 403.
func (s *Server) banDebanActionsAvailable() bool {
	return s.banDebanner != nil && s.cfg.UI.MutationsEnabled && s.cfg.Cloudflare.MutationsEnabled
}

func (s *Server) handleBanLifecycleDeban(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.UI.MutationsEnabled {
		http.Error(w, "ui mutations disabled", http.StatusForbidden)
		return
	}
	if !s.cfg.Cloudflare.MutationsEnabled {
		http.Error(w, "cloudflare mutations disabled", http.StatusForbidden)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if s.banDebanner == nil {
		http.Error(w, "deban capability not available on this instance", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ip := r.PostForm.Get("ip")
	if net.ParseIP(ip) == nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}
	reason := r.PostForm.Get("reason")
	if reason == "" {
		reason = "operator-initiated deban via /ban-lifecycle"
	}

	eventID := newUIEventID()
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()
	err := s.banDebanner.DebanIP(ctx, ip, reason)
	result := "success"
	if err != nil {
		result = "failed"
	}
	s.audit.Record("ban_lifecycle_deban", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         ip,
		"result":         result,
		"correlation_id": eventID,
		"event_id":       eventID,
	})
	if err != nil {
		http.Error(w, "deban failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/ban-lifecycle", http.StatusSeeOther)
}

func (s *Server) handleBanLifecycleClearAll(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.UI.MutationsEnabled {
		http.Error(w, "ui mutations disabled", http.StatusForbidden)
		return
	}
	if !s.cfg.Cloudflare.MutationsEnabled {
		http.Error(w, "cloudflare mutations disabled", http.StatusForbidden)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if s.banDebanner == nil {
		http.Error(w, "deban capability not available on this instance", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("confirm") != "CLEAR" {
		http.Error(w, `type "CLEAR" to confirm`, http.StatusBadRequest)
		return
	}
	reason := r.PostForm.Get("reason")
	if reason == "" {
		reason = "operator-initiated bulk clear via /ban-lifecycle"
	}

	eventID := newUIEventID()
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()
	clearResult, err := s.banDebanner.ClearManagedBans(ctx, reason)
	result := "success"
	if err != nil {
		result = "failed"
	}
	s.audit.Record("ban_lifecycle_clear_all", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         "ban-lifecycle",
		"result":         result,
		"correlation_id": eventID,
		"event_id":       eventID,
		"attempted":      fmt.Sprintf("%d", clearResult.Attempted),
		"deleted":        fmt.Sprintf("%d", clearResult.Deleted),
		"failed":         fmt.Sprintf("%d", clearResult.Failed),
	})
	if err != nil {
		http.Error(w, "clear failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/ban-lifecycle", http.StatusSeeOther)
}

func BanLifecyclePage(view BanLifecycleView, actionsAvailable bool, csrfToken string) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Cloudflare Ban Lifecycle",
		Headline: "Cloudflare Ban Lifecycle",
		Subtitle: "Full history of local autoban lifecycle entries — active, expired, auto-debanned, and manually overridden — with recidive-aware durations. Managed bans only — manual Cloudflare rules are never shown or touched here. Debanning removes the Cloudflare rule; it never deletes AbuseIPDB report history or resets the AbuseIPDB reporting window.",
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
			if err := renderBanLifecycleClearAllPanel(w, actionsAvailable, csrfToken); err != nil {
				return err
			}
			if len(view.Entries) == 0 {
				return writeEmptyState(w, "No managed Cloudflare ban lifecycle entries yet.")
			}
			if _, err := fmt.Fprint(w, `<div style="overflow-x:auto"><table><thead><tr><th>IP</th><th>Source</th><th>Reason</th><th>Confidence</th><th>Recidive</th><th>Created</th><th>Expires</th><th>Duration</th><th>Rule ID</th><th>Status</th><th>Action</th></tr></thead><tbody>`); err != nil {
				return err
			}
			for _, entry := range view.Entries {
				if err := renderBanLifecycleRow(w, entry, actionsAvailable, csrfToken); err != nil {
					return err
				}
			}
			_, err := fmt.Fprint(w, `</tbody></table></div>`)
			return err
		}),
	})
}

func renderBanLifecycleClearAllPanel(w io.Writer, actionsAvailable bool, csrfToken string) error {
	if !actionsAvailable {
		_, err := fmt.Fprint(w, `<div class="panel"><span class="badge disabled">deban actions unavailable</span> <span class="muted" style="font-size:.85rem">Cloudflare mutations are disabled, or this instance has no Cloudflare deban capability wired.</span></div>`)
		return err
	}
	_, err := fmt.Fprintf(w,
		`<div class="panel"><form action="/actions/ban-lifecycle/clear" method="post" onsubmit="return confirm('This removes the Cloudflare rule for every currently-active managed ban. AbuseIPDB report history is never touched. Continue?');"><input type="hidden" name="csrf_token" value="%s"/><label>Clear all managed bans — type CLEAR to confirm</label><input type="text" name="confirm" autocomplete="off" placeholder="CLEAR"/><button type="submit" class="action-button secondary">Clear all managed bans</button></form><p class="muted" style="font-size:.85rem;margin-top:.5rem">Removes the Cloudflare rule for every active managed entry. AbuseIPDB report history and the 24h reporting window are never affected.</p></div>`,
		html.EscapeString(csrfToken),
	)
	return err
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
		lastAttempt := ""
		if !e.LastCleanupAttemptAt.IsZero() {
			lastAttempt = e.LastCleanupAttemptAt.UTC().Format("2006-01-02 15:04:05Z")
		}
		views = append(views, BanLifecycleEntryView{
			IP:                   e.IP,
			Source:               valueOrFallback(e.Source, "unknown"),
			Reason:               valueOrFallback(e.Reason, "unspecified"),
			Confidence:           e.Confidence,
			CreatedAt:            e.CreatedAt.UTC().Format("2006-01-02 15:04:05Z"),
			ExpiresAt:            e.ExpiresAt.UTC().Format("2006-01-02 15:04:05Z"),
			Duration:             e.Duration.String(),
			RuleID:               valueOrFallback(e.RuleID, "n/a"),
			RecidiveLevel:        e.RecidiveLevel,
			Status:               valueOrFallback(e.Status, "active"),
			CleanupRetrying:      e.Status == banlifecycle.StatusActive && e.CleanupAttempts > 0,
			CleanupAttempts:      e.CleanupAttempts,
			LastCleanupError:     e.LastCleanupError,
			LastCleanupAttemptAt: lastAttempt,
		})
	}
	return BanLifecycleView{Wired: true, Entries: views}
}

func renderBanLifecycleRow(w io.Writer, entry BanLifecycleEntryView, actionsAvailable bool, csrfToken string) error {
	recidiveBadge := `<span class="badge">1st</span>`
	switch {
	case entry.RecidiveLevel == 2:
		recidiveBadge = `<span class="badge warning">2nd</span>`
	case entry.RecidiveLevel >= 3:
		recidiveBadge = `<span class="badge error">3rd+</span>`
	}
	statusClass := "badge"
	statusLabel := entry.Status
	switch entry.Status {
	case "active":
		statusClass = "badge warning"
	case "auto_debanned":
		statusClass = "badge success"
	case "manual_override":
		statusClass = "badge error"
	case "operator_debanned":
		statusClass = "badge success"
	}
	if entry.CleanupRetrying {
		statusClass = "badge error"
		statusLabel = fmt.Sprintf("retrying cleanup (%d failed attempt(s))", entry.CleanupAttempts)
	}
	statusCell := fmt.Sprintf(`<span class="%s">%s</span>`, statusClass, html.EscapeString(statusLabel))
	if entry.CleanupRetrying {
		statusCell += fmt.Sprintf(
			`<div class="muted" style="font-size:.8rem">last attempt %s: %s</div>`,
			html.EscapeString(entry.LastCleanupAttemptAt), html.EscapeString(entry.LastCleanupError),
		)
	}
	if _, err := fmt.Fprintf(w,
		`<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>`,
		html.EscapeString(entry.IP),
		html.EscapeString(entry.Source),
		html.EscapeString(entry.Reason),
		entry.Confidence,
		recidiveBadge,
		html.EscapeString(entry.CreatedAt),
		html.EscapeString(entry.ExpiresAt),
		html.EscapeString(entry.Duration),
		html.EscapeString(entry.RuleID),
		statusCell,
	); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, `<td>`); err != nil {
		return err
	}
	if actionsAvailable && entry.Status == "active" {
		if _, err := fmt.Fprintf(w,
			`<form action="/actions/ban-lifecycle/deban" method="post" onsubmit="return confirm('Remove the Cloudflare rule for %s? AbuseIPDB report history is never touched.');"><input type="hidden" name="csrf_token" value="%s"/><input type="hidden" name="ip" value="%s"/><button type="submit" class="action-button secondary">Deban</button></form>`,
			html.EscapeString(entry.IP), html.EscapeString(csrfToken), html.EscapeString(entry.IP),
		); err != nil {
			return err
		}
	} else if entry.Status != "active" {
		if _, err := fmt.Fprint(w, `<span class="muted">—</span>`); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</td></tr>`)
	return err
}
