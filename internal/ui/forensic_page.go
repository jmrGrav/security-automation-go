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

func renderForensicPage(ctx context.Context, w http.ResponseWriter, view ForensicView) {
	_ = ForensicPage(view).Render(ctx, w)
}

func ForensicPage(view ForensicView) templ.Component {
	body := templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		escaped := html.EscapeString(view.IP)

		if _, err := fmt.Fprint(w, `<section class="grid"><div class="panel"><h2>Forensic IP Lookup</h2><form action="/forensic" method="post"><label for="ip">IP address</label><input id="ip" name="ip" type="text" value="`); err != nil {
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

		if !view.HasData {
			if _, err := fmt.Fprint(w, `</section>`); err != nil {
				return err
			}
			return nil
		}

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

		if _, err := fmt.Fprintf(w, `<div class="panel"><h2>%s %s%s</h2>`, html.EscapeString(s.IP.String()), cacheBadge, protectedBadge); err != nil {
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

		asnText := "unknown"
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

		if _, err := fmt.Fprint(w, `</div></div></section>`); err != nil {
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
