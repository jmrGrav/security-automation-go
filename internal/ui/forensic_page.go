package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"

	"github.com/a-h/templ"
)

func renderForensicPage(ctx context.Context, w http.ResponseWriter, view ForensicView, csrfToken string) {
	_ = ForensicPage(view, csrfToken).Render(ctx, w)
}

func ForensicPage(view ForensicView, csrfToken string) templ.Component {
	body := templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		escaped := html.EscapeString(view.IP)

		if _, err := fmt.Fprint(w, `<div data-live-panel-content data-live-panel-title="Forensic Lookup"><section class="grid"><div class="panel"><h2>Forensic IP Lookup</h2><form action="/forensic" method="post"><input type="hidden" name="csrf_token" value="`); err != nil {
			return err
		}
		if _, err := io.WriteString(w, html.EscapeString(csrfToken)); err != nil {
			return err
		}
		if _, err := fmt.Fprint(w, `"/><label for="ip">IP address</label><input id="ip" name="ip" type="text" value="`); err != nil {
			return err
		}
		if _, err := io.WriteString(w, escaped); err != nil {
			return err
		}
		if _, err := fmt.Fprint(w, `" placeholder="e.g. 203.0.113.1" autocomplete="off"/><button type="submit">Look up</button></form></div>`); err != nil {
			return err
		}

		if view.Error != "" {
			if _, err := fmt.Fprint(w, `<div class="panel"><p class="error">`); err != nil {
				return err
			}
			if _, err := io.WriteString(w, html.EscapeString(view.Error)); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `</p></div>`); err != nil {
				return err
			}
		}

		if view.EnrichmentError != "" {
			if _, err := fmt.Fprint(w, `<div class="panel"><p class="error">`); err != nil {
				return err
			}
			if _, err := io.WriteString(w, html.EscapeString(view.EnrichmentError)); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `</p></div>`); err != nil {
				return err
			}
		}

		if !view.HasData {
			if _, err := fmt.Fprint(w, `</section></div>`); err != nil {
				return err
			}
			return nil
		}

		if view.HasEnrichment {
			s := view.Summary
			a := view.Assess

			cacheBadge := `<span class="badge">fresh</span>`
			if s.CacheHit {
				cacheBadge = `<span class="badge warning">cache hit</span>`
			}
			protectedBadge := ""
			if a.NoHardBan {
				protectedBadge = ` <span class="badge healthy">protected network</span>`
			}

			watchBtn := fmt.Sprintf(`<button type="button" class="badge" data-watchlist-add="true" data-watchlist-type="ip" data-watchlist-value="%s" data-watchlist-label="%s" title="Add to watchlist" style="min-height:auto;padding:.12rem .4rem;font-size:.85rem;box-shadow:none;vertical-align:middle">☆</button>`,
				html.EscapeString(s.IP.String()),
				html.EscapeString(s.IP.String()),
			)
			if _, err := fmt.Fprintf(w, `<div class="panel"><h2>%s %s%s%s</h2>`, html.EscapeString(s.IP.String()), cacheBadge, protectedBadge, watchBtn); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, `<p class="muted">Score delta: %+d &nbsp; HardBan allowed: %s</p>`, a.Score, boolBadge(a.HardBanAllowed)); err != nil {
				return err
			}
			if len(a.Reasons) > 0 {
				if _, err := fmt.Fprintf(w, `<p class="muted">Signals: %s</p>`, html.EscapeString(strings.Join(a.Reasons, ", "))); err != nil {
					return err
				}
			}

			if _, err := fmt.Fprint(w, `<div class="kv">`); err != nil {
				return err
			}

			dnsStatus := "no PTR"
			if s.DNS.Hostname != "" {
				dnsStatus = html.EscapeString(s.DNS.Hostname)
				if s.DNS.Confirmed {
					dnsStatus += ` <span class="badge healthy">forward confirmed</span>`
				} else {
					dnsStatus += ` <span class="badge warning">rDNS unconfirmed</span>`
				}
				if s.DNS.TrustedBot {
					dnsStatus += ` <span class="badge healthy">trusted bot</span>`
				}
			}
			if _, err := fmt.Fprintf(w, `<div class="row"><span>DNS/rDNS</span><span>%s</span></div>`, dnsStatus); err != nil {
				return err
			}

			asnText := "not configured"
			if s.ASN.Org != "" {
				asnText = html.EscapeString(s.ASN.Org)
			}
			if s.ASN.Network != "" {
				asnText += " (" + html.EscapeString(s.ASN.Network) + ")"
			}
			asnKindBadge := ""
			switch {
			case s.ASN.Protected:
				asnKindBadge = ` <span class="badge healthy">protected</span>`
			case string(s.ASN.Kind) == "datacenter":
				asnKindBadge = ` <span class="badge warning">datacenter</span>`
			}
			if _, err := fmt.Fprintf(w, `<div class="row"><span>ASN/Network</span><span>%s%s</span></div>`, asnText, asnKindBadge); err != nil {
				return err
			}

			for _, v := range s.Providers {
				scoreBadge := badgeForScore(v.Score)
				label := html.EscapeString(v.Provider)
				if v.Manual {
					label += " (manual)"
				}
				note := ""
				if v.Note != "" {
					note = " — " + html.EscapeString(v.Note)
				}
				if _, err := fmt.Fprintf(w, `<div class="row"><span>%s</span><span>score %d %s%s</span></div>`, label, v.Score, scoreBadge, note); err != nil {
					return err
				}
			}

			if _, err := fmt.Fprint(w, `</div></div>`); err != nil {
				return err
			}
		}

		if len(view.LocalEvidence) > 0 {
			if _, err := fmt.Fprint(w, `<div class="panel"><h2>Local Evidence History</h2><div class="table-wrap"><table><colgroup><col style="width:12rem"><col style="width:9rem"><col style="width:8rem"><col style="width:4rem"><col style="width:8rem"><col></colgroup><thead><tr><th>timestamp</th><th>source</th><th>type</th><th>score</th><th>decision</th><th>status</th></tr></thead><tbody>`); err != nil {
				return err
			}
			for _, ev := range view.LocalEvidence {
				statusBadge := `<span class="badge">pending</span>`
				switch {
				case ev.AbuseIPDBReported:
					statusBadge = `<span class="badge bad">reported to AbuseIPDB</span>`
				case ev.Suppressed:
					statusBadge = `<span class="badge warning">suppressed: ` + html.EscapeString(ev.SuppressionReason) + `</span>`
				case ev.Decision == "report_pending":
					statusBadge = `<span class="badge live">report pending</span>`
				}
				if _, err := fmt.Fprintf(w, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td></tr>`,
					html.EscapeString(ev.Timestamp.Format("2006-01-02 15:04:05")),
					html.EscapeString(ev.Source),
					html.EscapeString(ev.AbuseType),
					ev.RiskScore,
					html.EscapeString(ev.Decision),
					statusBadge,
				); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `</tbody></table></div></div>`); err != nil {
				return err
			}
		}

		if view.NoteFormHTML != "" {
			if _, err := io.WriteString(w, view.NoteFormHTML); err != nil {
				return err
			}
		}

		if _, err := fmt.Fprint(w, `</section></div>`); err != nil {
			return err
		}
		return nil
	})

	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		return ConsoleLayout(shellView{
			Title:    "Forensic Lookup",
			Headline: "Forensic IP Lookup",
			Subtitle: "Local enrichment summary, DNS/rDNS, ASN, and provider signals.",
			Active:   "/forensic",
			Body:     body,
		}).Render(ctx, w)
	})
}

func boolBadge(v bool) string {
	if v {
		return `<span class="badge bad">yes</span>`
	}
	return `<span class="badge ok">no</span>`
}

func badgeForScore(score int) string {
	switch {
	case score >= 90:
		return `<span class="badge bad">high</span>`
	case score >= 70:
		return `<span class="badge warn">elevated</span>`
	case score > 0:
		return `<span class="badge">low</span>`
	default:
		return `<span class="badge ok">none</span>`
	}
}
