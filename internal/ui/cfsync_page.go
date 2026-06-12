package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"time"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/shadow"
)

func (s *Server) buildCFSyncView() CFSyncView {
	store := shadow.NewStore(s.cfg.StateDir)
	all, err := store.ReadAll()
	if err != nil {
		return CFSyncView{Error: err.Error()}
	}
	if len(all) == 0 {
		return CFSyncView{CycleCount: 0}
	}
	latest := all[len(all)-1]
	return CFSyncView{
		HasData:      true,
		CycleAt:      latest.CycleAt,
		AgreementPct: latest.AgreementPct,
		InSync:       latest.InSync,
		ToAdd:        latest.PlannedAdds,
		ToDelete:     latest.PlannedDeletes,
		ActiveBans:   latest.ActiveBanCount,
		CFRules:      latest.CFRuleCount,
		CycleCount:   len(all),
	}
}

func (s *Server) handleCFSyncPage(w http.ResponseWriter, r *http.Request) {
	view := s.buildCFSyncView()
	_ = CFSyncPage(view).Render(r.Context(), w)
}

// CFSyncPage renders the /sync page.
func CFSyncPage(view CFSyncView) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "CF Ban Sync",
		Headline: "Cloudflare Ban Sync",
		Subtitle: "Latest computed sync plan: IPs to add/remove in the next enforcement cycle.",
		Active:   "/sync",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			return renderCFSyncBody(w, view)
		}),
	})
}

func renderCFSyncBody(w io.Writer, view CFSyncView) error {
	if view.Error != "" {
		_, err := fmt.Fprintf(w,
			`<div class="panel"><p class="error">Error loading sync data: %s</p></div>`,
			html.EscapeString(view.Error),
		)
		return err
	}

	if !view.HasData {
		_, err := fmt.Fprint(w,
			`<div class="panel"><p class="muted">No sync cycles recorded yet. The daemon must run at least one enforcement cycle before data appears here.</p></div>`,
		)
		return err
	}

	syncBadge := `<span class="badge healthy">IN SYNC</span>`
	if !view.InSync {
		syncBadge = `<span class="badge error">DRIFT DETECTED</span>`
	}

	age := time.Since(view.CycleAt).Truncate(time.Second)
	if _, err := fmt.Fprintf(w,
		`<div class="panel"><h2>Last Cycle Summary</h2>`+
			`<div class="badges" style="margin-bottom:.75rem">%s</div>`+
			`<div class="kv">`+
			`<div class="row"><span>Last cycle</span><span>%s (%s ago)</span></div>`+
			`<div class="row"><span>Agreement</span><span>%.2f%%</span></div>`+
			`<div class="row"><span>Active CrowdSec bans</span><span>%d</span></div>`+
			`<div class="row"><span>Cloudflare rules (watched tag)</span><span>%d</span></div>`+
			`<div class="row"><span>Total cycles recorded</span><span>%d</span></div>`+
			`</div></div>`,
		syncBadge,
		html.EscapeString(view.CycleAt.UTC().Format(time.RFC3339)),
		html.EscapeString(age.String()),
		view.AgreementPct,
		view.ActiveBans,
		view.CFRules,
		view.CycleCount,
	); err != nil {
		return err
	}

	if err := renderSyncIPList(w, "To Add", "IPs Go would add to Cloudflare (active bans not yet in CF)", view.ToAdd, "healthy"); err != nil {
		return err
	}
	return renderSyncIPList(w, "To Delete", "IPs Go would remove from Cloudflare (CF rules with no active ban)", view.ToDelete, "error")
}

func renderSyncIPList(w io.Writer, title, desc string, ips []string, badgeClass string) error {
	count := len(ips)
	countBadge := fmt.Sprintf(`<span class="badge %s">%d</span>`, badgeClass, count)
	if count == 0 {
		countBadge = `<span class="badge">0</span>`
	}

	if _, err := fmt.Fprintf(w,
		`<div class="panel"><h2>%s %s</h2><p class="muted">%s</p>`,
		html.EscapeString(title), countBadge, html.EscapeString(desc),
	); err != nil {
		return err
	}

	if count == 0 {
		if _, err := fmt.Fprint(w, `<p class="muted">None.</p>`); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprint(w, `<div class="kv">`); err != nil {
			return err
		}
		display := ips
		truncated := false
		if len(display) > 200 {
			display = display[:200]
			truncated = true
		}
		for _, ip := range display {
			if _, err := fmt.Fprintf(w,
				`<div class="row"><span><code>%s</code></span></div>`,
				html.EscapeString(ip),
			); err != nil {
				return err
			}
		}
		if truncated {
			if _, err := fmt.Fprintf(w,
				`<div class="row"><span class="muted">… and %d more (showing first 200)</span></div>`,
				len(ips)-200,
			); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(w, `</div>`); err != nil {
			return err
		}
	}

	_, err := fmt.Fprint(w, `</div>`)
	return err
}
