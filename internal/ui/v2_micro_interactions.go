package ui

import (
	"fmt"
	"html"
)

// bannerPalette holds inline-style colours for a single banner level.
type bannerPalette struct {
	bg     string
	border string
	text   string
}

var v2BannerPalettes = map[string]bannerPalette{
	"ok":    {bg: "rgba(76,199,154,.08)", border: "rgba(76,199,154,.18)", text: "#4cc79a"},
	"warn":  {bg: "rgba(245,146,30,.08)", border: "rgba(245,146,30,.18)", text: "#f5a443"},
	"error": {bg: "rgba(239,95,107,.08)", border: "rgba(239,95,107,.18)", text: "#ef5f6b"},
	"info":  {bg: "rgba(124,108,242,.08)", border: "rgba(124,108,242,.18)", text: "#9b8cff"},
}

// renderV2StatusBanner renders a coloured situation strip at the top of a page.
// level: "ok" | "warn" | "error" | "info"
// title: short bold prefix (e.g. "● HEALTHY")
// primary: main message text
// secondary: optional secondary detail (pass "" to omit)
// ctaHref/ctaLabel: optional call-to-action link (pass "" to omit)
func renderV2StatusBanner(level, title, primary, secondary, ctaHref, ctaLabel string) string {
	p, ok := v2BannerPalettes[level]
	if !ok {
		p = v2BannerPalettes["info"]
	}

	secondaryHTML := ""
	if secondary != "" {
		secondaryHTML = fmt.Sprintf(
			`<span style="color:#8b8fa8;margin-left:12px;font-size:.82rem;">%s</span>`,
			html.EscapeString(secondary),
		)
	}

	ctaHTML := ""
	if ctaHref != "" && ctaLabel != "" {
		ctaHTML = fmt.Sprintf(
			`<a href="%s" style="margin-left:auto;color:%s;font-size:.82rem;text-decoration:none;border-bottom:1px solid %s;white-space:nowrap;">%s</a>`,
			html.EscapeString(ctaHref),
			p.text,
			p.border,
			html.EscapeString(ctaLabel),
		)
	}

	return fmt.Sprintf(
		`<div style="display:flex;align-items:center;gap:8px;padding:10px 16px;background:%s;border:1px solid %s;border-radius:6px;margin-bottom:16px;">
  <span style="color:%s;font-weight:700;font-size:.85rem;white-space:nowrap;">%s</span>
  <span style="color:#c9cdd6;font-size:.85rem;">%s</span>%s%s
</div>`,
		p.bg,
		p.border,
		p.text,
		html.EscapeString(title),
		html.EscapeString(primary),
		secondaryHTML,
		ctaHTML,
	)
}

// renderV2SectionHeader renders an eyebrow + title + detail line.
// eyebrow: small uppercase label above the title (e.g. "INFRASTRUCTURE")
// title: main heading text
// detail: optional supporting line below (pass "" to omit)
func renderV2SectionHeader(title, eyebrow, detail string) string {
	detailHTML := ""
	if detail != "" {
		detailHTML = fmt.Sprintf(
			`<div style="color:#8b8fa8;font-size:.82rem;margin-top:2px;">%s</div>`,
			html.EscapeString(detail),
		)
	}

	return fmt.Sprintf(
		`<div style="margin-bottom:20px;">
  <div style="color:#7c6cf2;font-size:.7rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;margin-bottom:4px;">%s</div>
  <div style="color:#e2e4ec;font-size:1.15rem;font-weight:600;">%s</div>%s
</div>`,
		html.EscapeString(eyebrow),
		html.EscapeString(title),
		detailHTML,
	)
}

// renderV2FreshnessStamp renders a "last updated X ago" stamp for live data.
// label: e.g. "refreshed"
// value: e.g. "2m ago"
func renderV2FreshnessStamp(label, value string) string {
	return fmt.Sprintf(
		`<span style="color:#8b8fa8;font-size:.75rem;">%s <span style="color:#c9cdd6;">%s</span></span>`,
		html.EscapeString(label),
		html.EscapeString(value),
	)
}

// renderV2ActionHint renders a small inline call-to-action link.
func renderV2ActionHint(label, href string) string {
	return fmt.Sprintf(
		`<a href="%s" style="color:#7c6cf2;font-size:.8rem;text-decoration:none;border-bottom:1px solid rgba(124,108,242,.3);">%s</a>`,
		html.EscapeString(href),
		html.EscapeString(label),
	)
}
