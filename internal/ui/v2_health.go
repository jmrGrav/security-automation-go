package ui

import (
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/detect"
	"github.com/jm/security-automation-go/internal/health"
)

func (s *Server) handleV2Health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()

	checks := health.RunAll(s.buildHealthConfig())
	detectors := detect.RunAll(s.buildDetectConfig())
	pipelineView := s.buildPipelineHealthView(ctx)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, renderV2HealthPage(checks, detectors, pipelineView))
}

func renderV2HealthPage(checks []health.Check, detectors []detect.Result, pipeline PipelineHealthView) string {
	green, yellow, red := 0, 0, 0
	for _, c := range checks {
		switch c.Status {
		case health.Green:
			green++
		case health.Yellow:
			yellow++
		case health.Red:
			red++
		}
	}
	total := len(checks)
	allGreen := yellow == 0 && red == 0

	// Posture
	var sb strings.Builder
	sb.WriteString(`<div style="background:#13151c;border:1px solid #242838;border-radius:12px;overflow:hidden;color:#e8eaf1">`)

	// Topbar
	sb.WriteString(`<div style="display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid #20242f">`)
	sb.WriteString(`<span style="font:700 14px 'Hanken Grotesk',sans-serif;color:#eef0f6">System Health</span>`)
	sb.WriteString(`<span style="font:500 12px 'JetBrains Mono',monospace;color:#6b7184">· health + pipeline</span>`)
	sb.WriteString(`<span style="flex:1"></span>`)
	sb.WriteString(`<a href="/health/diagnostic" style="display:inline-flex;align-items:center;gap:6px;padding:5px 11px;border-radius:7px;background:#1c2030;border:1px solid #2a2f42;font:600 11px 'Hanken Grotesk',sans-serif;color:#c5cad8;text-decoration:none">Run diagnostic</a>`)
	sb.WriteString(`<a href="/health/support-bundle" style="display:inline-flex;align-items:center;gap:6px;padding:5px 11px;border-radius:7px;background:rgba(124,108,242,.14);border:1px solid rgba(124,108,242,.3);font:600 11px 'Hanken Grotesk',sans-serif;color:#a99cff;text-decoration:none">Support bundle</a>`)
	sb.WriteString(`</div>`)

	// Posture strip
	sb.WriteString(`<div style="padding:18px;border-bottom:1px solid #20242f">`)
	sb.WriteString(`<div style="display:flex;align-items:center;gap:14px">`)
	if allGreen {
		sb.WriteString(`<span style="width:14px;height:14px;border-radius:50%;background:#4cc79a;box-shadow:0 0 0 4px rgba(76,199,154,.15);flex:none"></span>`)
	} else {
		sb.WriteString(`<span style="width:14px;height:14px;border-radius:50%;background:#f5921e;box-shadow:0 0 0 4px rgba(245,146,30,.15);flex:none"></span>`)
	}
	sb.WriteString(`<div style="flex:1">`)
	if allGreen {
		sb.WriteString(`<div style="font:700 20px 'Hanken Grotesk',sans-serif;color:#eef0f6">All systems operational</div>`)
	} else {
		sb.WriteString(fmt.Sprintf(`<div style="font:700 20px 'Hanken Grotesk',sans-serif;color:#eef0f6">%d issue(s) detected</div>`, yellow+red))
	}
	sb.WriteString(fmt.Sprintf(
		`<div style="font:500 12px 'JetBrains Mono',monospace;color:#6b7184;margin-top:2px">as of %s · %d/%d subsystems · pipeline %s</div>`,
		time.Now().UTC().Format("2006-01-02T15:04Z"),
		len(detectors), len(detectors),
		func() string {
			if pipeline.Total.Classified > 0 {
				return "active"
			}
			return "idle"
		}(),
	))
	sb.WriteString(`</div>`)
	// Summary chips
	sb.WriteString(`<div style="display:flex;gap:7px">`)
	sb.WriteString(fmt.Sprintf(
		`<span style="font:600 11px 'JetBrains Mono',monospace;color:#54c79a;background:rgba(76,199,154,.12);border:1px solid rgba(76,199,154,.22);padding:3px 9px;border-radius:6px">%d green</span>`,
		green,
	))
	warnColor := "#6b7184"
	warnBg := "rgba(255,255,255,.04)"
	warnBorder := "rgba(255,255,255,.07)"
	if yellow > 0 {
		warnColor = "#f5b563"
		warnBg = "rgba(245,146,30,.10)"
		warnBorder = "rgba(245,146,30,.22)"
	}
	sb.WriteString(fmt.Sprintf(
		`<span style="font:600 11px 'JetBrains Mono',monospace;color:%s;background:%s;border:1px solid %s;padding:3px 9px;border-radius:6px">%d warning</span>`,
		warnColor, warnBg, warnBorder, yellow,
	))
	errColor := "#6b7184"
	errBg := "rgba(255,255,255,.04)"
	errBorder := "rgba(255,255,255,.07)"
	if red > 0 {
		errColor = "#f08591"
		errBg = "rgba(239,95,107,.10)"
		errBorder = "rgba(239,95,107,.22)"
	}
	sb.WriteString(fmt.Sprintf(
		`<span style="font:600 11px 'JetBrains Mono',monospace;color:%s;background:%s;border:1px solid %s;padding:3px 9px;border-radius:6px">%d error</span>`,
		errColor, errBg, errBorder, red,
	))
	sb.WriteString(`</div>`) // chips
	sb.WriteString(`</div>`) // flex row

	// Advisories: any non-green checks
	advisories := collectAdvisories(checks)
	if len(advisories) > 0 {
		for _, adv := range advisories {
			bgColor := "rgba(245,146,30,.07)"
			borderColor := "rgba(245,146,30,.2)"
			dotColor := "#f5921e"
			labelColor := "#f5b563"
			if adv.level == health.Red {
				bgColor = "rgba(239,95,107,.07)"
				borderColor = "rgba(239,95,107,.2)"
				dotColor = "#ef5f6b"
				labelColor = "#f08591"
			}
			sb.WriteString(fmt.Sprintf(
				`<div style="display:flex;align-items:flex-start;gap:10px;margin-top:12px;padding:10px 12px;border-radius:9px;background:%s;border:1px solid %s">`,
				bgColor, borderColor,
			))
			sb.WriteString(fmt.Sprintf(`<span style="width:7px;height:7px;border-radius:50%%;background:%s;flex:none;margin-top:3px"></span>`, dotColor))
			sb.WriteString(fmt.Sprintf(`<span style="font:600 12px 'Hanken Grotesk',sans-serif;color:%s;white-space:nowrap">%s advisory</span>`, labelColor, adv.level))
			detail := adv.reason
			if adv.remediation != "" {
				detail += " — " + adv.remediation
			}
			sb.WriteString(fmt.Sprintf(`<span style="font:500 12px 'Hanken Grotesk',sans-serif;color:#aab0c2;flex:1">%s</span>`, html.EscapeString(adv.name)+`: `+html.EscapeString(detail)))
			sb.WriteString(`</div>`)
		}
	}
	sb.WriteString(`</div>`) // posture

	// Pipeline funnel hero
	if pipeline.Error == "" {
		sb.WriteString(renderV2HealthFunnel(pipeline))
	}

	// Per-source rows
	if pipeline.Error == "" {
		sb.WriteString(renderV2HealthSources(pipeline))
	}

	// Subsystems 3×3 grid
	sb.WriteString(renderV2HealthSubsystems(detectors))

	// Health checks collapsed chips
	sb.WriteString(renderV2HealthChecks(checks, total, green))

	sb.WriteString(`</div>`) // outer card

	return v2Page("System Health", "/v2/health", sb.String())
}

type v2Advisory struct {
	level       health.Level
	name        string
	reason      string
	remediation string
}

func collectAdvisories(checks []health.Check) []v2Advisory {
	var out []v2Advisory
	for _, c := range checks {
		if c.Status == health.Green {
			continue
		}
		out = append(out, v2Advisory{
			level:       c.Status,
			name:        c.Name,
			reason:      c.Reason,
			remediation: c.Remediation,
		})
	}
	return out
}

func renderV2HealthFunnel(pipeline PipelineHealthView) string {
	t := pipeline.Total
	classified := t.Classified
	suppressed := t.Suppressed
	pending := t.Pending
	reported := t.Reported

	suppPct := 0.0
	pendPct := 0.0
	repPct := 0.0
	if classified > 0 {
		suppPct = float64(suppressed) / float64(classified) * 100
		pendPct = float64(pending) / float64(classified) * 100
		repPct = float64(reported) / float64(classified) * 100
	}

	activeSources := 0
	for _, r := range pipeline.Rows {
		if r.Classified > 0 {
			activeSources++
		}
	}

	var sb strings.Builder
	sb.WriteString(`<div style="padding:18px;border-bottom:1px solid #20242f">`)
	// Section header
	sb.WriteString(`<div style="display:flex;align-items:center;margin-bottom:14px">`)
	sb.WriteString(`<span style="font:700 11px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase">Event pipeline</span>`)
	sb.WriteString(`<span style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184;margin-left:8px">last 24h</span>`)
	sb.WriteString(`<span style="flex:1"></span>`)
	sb.WriteString(`<span class="v2-live-badge"><span class="v2-live-dot"></span>LIVE</span>`)
	sb.WriteString(`</div>`)

	// Classified total + outcome tiles
	sb.WriteString(`<div style="display:flex;align-items:stretch;gap:14px">`)

	// Left: classified total
	sb.WriteString(`<div style="flex:none;width:150px;border:1px solid #20242f;border-radius:10px;background:#10121a;padding:14px">`)
	sb.WriteString(`<div style="font:600 10px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase">Classified</div>`)
	sb.WriteString(fmt.Sprintf(`<div style="font:700 30px/1 'Hanken Grotesk',sans-serif;color:#eef0f6;margin-top:8px">%s</div>`, fmtCount(classified)))
	sb.WriteString(fmt.Sprintf(`<div style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184;margin-top:6px">%d sources active</div>`, activeSources))
	sb.WriteString(`</div>`)

	// Right: outcome tiles + bar
	sb.WriteString(`<div style="flex:1;display:flex;flex-direction:column;gap:10px">`)
	sb.WriteString(`<div style="display:flex;gap:10px">`)

	// Suppressed
	sb.WriteString(`<div style="flex:1;border:1px solid rgba(124,108,242,.22);border-radius:10px;background:rgba(124,108,242,.06);padding:11px 13px">`)
	sb.WriteString(`<div style="display:flex;align-items:center;gap:6px"><span style="width:7px;height:7px;border-radius:50%;background:#7c6cf2"></span><span style="font:600 11px 'Hanken Grotesk',sans-serif;color:#a99cff">Suppressed</span></div>`)
	sb.WriteString(fmt.Sprintf(`<div style="font:700 22px 'Hanken Grotesk',sans-serif;color:#eef0f6;margin-top:5px">%s</div>`, fmtCount(suppressed)))
	sb.WriteString(fmt.Sprintf(`<div style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184">%.1f%%</div>`, suppPct))
	sb.WriteString(`</div>`)

	// Pending
	sb.WriteString(`<div style="flex:1;border:1px solid rgba(245,146,30,.22);border-radius:10px;background:rgba(245,146,30,.06);padding:11px 13px">`)
	sb.WriteString(`<div style="display:flex;align-items:center;gap:6px"><span style="width:7px;height:7px;border-radius:50%;background:#f5921e"></span><span style="font:600 11px 'Hanken Grotesk',sans-serif;color:#f5b563">Pending</span></div>`)
	sb.WriteString(fmt.Sprintf(`<div style="font:700 22px 'Hanken Grotesk',sans-serif;color:#eef0f6;margin-top:5px">%s</div>`, fmtCount(pending)))
	sb.WriteString(fmt.Sprintf(`<div style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184">%.1f%%</div>`, pendPct))
	sb.WriteString(`</div>`)

	// Reported
	sb.WriteString(`<div style="flex:1;border:1px solid rgba(76,199,154,.22);border-radius:10px;background:rgba(76,199,154,.06);padding:11px 13px">`)
	sb.WriteString(`<div style="display:flex;align-items:center;gap:6px"><span style="width:7px;height:7px;border-radius:50%;background:#4cc79a"></span><span style="font:600 11px 'Hanken Grotesk',sans-serif;color:#54c79a">Reported</span></div>`)
	sb.WriteString(fmt.Sprintf(`<div style="font:700 22px 'Hanken Grotesk',sans-serif;color:#eef0f6;margin-top:5px">%s</div>`, fmtCount(reported)))
	sb.WriteString(`<div style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184">→ AbuseIPDB</div>`)
	sb.WriteString(`</div>`)

	sb.WriteString(`</div>`) // tiles row

	// Proportion bar
	sb.WriteString(`<div style="display:flex;height:10px;border-radius:5px;overflow:hidden;background:#10121a">`)
	if suppPct > 0 {
		sb.WriteString(fmt.Sprintf(`<span style="width:%.1f%%;background:#7c6cf2"></span>`, suppPct))
	}
	if pendPct > 0 {
		minW := pendPct
		if minW < 0.5 {
			minW = 0.5
		}
		sb.WriteString(fmt.Sprintf(`<span style="width:%.1f%%;background:#f5921e;min-width:3px"></span>`, minW))
	}
	if repPct > 0 {
		minW := repPct
		if minW < 0.5 {
			minW = 0.5
		}
		sb.WriteString(fmt.Sprintf(`<span style="width:%.1f%%;background:#4cc79a;min-width:3px"></span>`, minW))
	}
	sb.WriteString(`<span style="flex:1;background:#1c2030"></span>`)
	sb.WriteString(`</div>`)

	sb.WriteString(`</div>`) // right column
	sb.WriteString(`</div>`) // row

	// Suppression breakdown chips
	bd := t.SuppressionBreakdown
	var chips []string
	if bd.ProtectedTarget > 0 {
		chips = append(chips, fmt.Sprintf(`<span style="color:#787f93">protected_target</span> %s`, fmtCount(bd.ProtectedTarget)))
	}
	if bd.BenignSignal > 0 {
		chips = append(chips, fmt.Sprintf(`<span style="color:#787f93">benign_signal</span> %s`, fmtCount(bd.BenignSignal)))
	}
	if bd.DuplicateReport > 0 {
		chips = append(chips, fmt.Sprintf(`<span style="color:#787f93">duplicate</span> %s`, fmtCount(bd.DuplicateReport)))
	}
	if bd.RecentlyReported > 0 {
		chips = append(chips, fmt.Sprintf(`<span style="color:#787f93">recently_reported</span> %s`, fmtCount(bd.RecentlyReported)))
	}
	if bd.LowConfidence > 0 {
		chips = append(chips, fmt.Sprintf(`<span style="color:#787f93">low_confidence</span> %s`, fmtCount(bd.LowConfidence)))
	}
	if bd.NoCategories > 0 {
		chips = append(chips, fmt.Sprintf(`<span style="color:#787f93">no_categories</span> %s`, fmtCount(bd.NoCategories)))
	}
	if len(chips) > 0 {
		sb.WriteString(`<div style="display:flex;flex-wrap:wrap;gap:7px;margin-top:13px">`)
		for _, chip := range chips {
			sb.WriteString(fmt.Sprintf(
				`<span style="font:500 11px 'JetBrains Mono',monospace;color:#aab0c2;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);padding:3px 8px;border-radius:6px">%s</span>`,
				chip,
			))
		}
		sb.WriteString(`</div>`)
	}

	sb.WriteString(`</div>`) // section
	return sb.String()
}

func renderV2HealthSources(pipeline PipelineHealthView) string {
	var sb strings.Builder
	sb.WriteString(`<div style="padding:16px 18px;border-bottom:1px solid #20242f">`)
	sb.WriteString(`<div style="font:700 11px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase;margin-bottom:12px">By source</div>`)
	sb.WriteString(`<div style="display:flex;flex-direction:column;gap:11px">`)

	for _, row := range pipeline.Rows {
		active := row.Classified > 0
		stateLabel := "idle"
		stateBg := "rgba(255,255,255,.04)"
		stateColor := "#7b8196"
		nameColor := "#9aa0b2"
		if active {
			stateLabel = "active"
			stateBg = "rgba(76,199,154,.12)"
			stateColor = "#54c79a"
			nameColor = "#e3e6ef"
		}

		// Mini proportion bar
		var barHTML strings.Builder
		if row.Classified > 0 {
			sp := float64(row.Suppressed) / float64(row.Classified) * 100
			pp := float64(row.Pending) / float64(row.Classified) * 100
			rp := float64(row.Reported) / float64(row.Classified) * 100
			barHTML.WriteString(fmt.Sprintf(`<span style="width:%.1f%%;background:#7c6cf2"></span>`, sp))
			if pp > 0 {
				barHTML.WriteString(fmt.Sprintf(`<span style="width:%.1f%%;background:#f5921e;min-width:2px"></span>`, pp))
			}
			if rp > 0 {
				barHTML.WriteString(fmt.Sprintf(`<span style="width:%.1f%%;background:#4cc79a;min-width:2px"></span>`, rp))
			}
		}

		freshColor := "#6b7184"
		if active && (row.Freshness == "just now" || strings.HasSuffix(row.Freshness, "m ago")) {
			freshColor = "#54c79a"
		}

		sb.WriteString(`<div style="display:flex;align-items:center;gap:12px">`)
		sb.WriteString(fmt.Sprintf(`<span style="width:140px;font:600 13px 'Hanken Grotesk',sans-serif;color:%s">%s</span>`, nameColor, html.EscapeString(row.Source)))
		sb.WriteString(fmt.Sprintf(`<span style="font:600 10px 'JetBrains Mono',monospace;color:%s;background:%s;padding:2px 7px;border-radius:5px">%s</span>`, stateColor, stateBg, stateLabel))
		sb.WriteString(fmt.Sprintf(`<span style="flex:1;height:7px;border-radius:4px;background:#10121a;display:flex;overflow:hidden">%s</span>`, barHTML.String()))
		sb.WriteString(fmt.Sprintf(`<span style="width:64px;text-align:right;font:600 12px 'JetBrains Mono',monospace;color:%s">%s</span>`, nameColor, fmtCount(row.Classified)))
		sb.WriteString(fmt.Sprintf(`<span style="width:72px;text-align:right;font:500 11px 'JetBrains Mono',monospace;color:%s">%s</span>`, freshColor, html.EscapeString(row.Freshness)))
		sb.WriteString(`</div>`)
	}

	sb.WriteString(`</div>`) // column
	sb.WriteString(`</div>`) // section
	return sb.String()
}

func renderV2HealthSubsystems(detectors []detect.Result) string {
	if len(detectors) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<div style="padding:16px 18px;border-bottom:1px solid #20242f">`)
	sb.WriteString(`<div style="display:flex;align-items:center;margin-bottom:12px">`)
	sb.WriteString(`<span style="font:700 11px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase">Subsystems</span>`)
	sb.WriteString(`<span style="flex:1"></span>`)
	sb.WriteString(`<span style="font:500 10px 'JetBrains Mono',monospace;color:#6b7184">● present &nbsp;● configured &nbsp;● healthy</span>`)
	sb.WriteString(`</div>`)
	sb.WriteString(`<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">`)
	for _, d := range detectors {
		dotPresent := dotColor(d.Installed)
		dotConfigured := dotColor(d.Configured)
		dotHealthy := dotColor(d.Healthy)

		detail := subsystemDetail(d)

		sb.WriteString(`<div style="border:1px solid #20242f;border-radius:9px;background:#10121a;padding:11px 12px">`)
		sb.WriteString(`<div style="display:flex;align-items:center">`)
		sb.WriteString(fmt.Sprintf(`<span style="flex:1;font:600 12px 'Hanken Grotesk',sans-serif;color:#e3e6ef">%s</span>`, html.EscapeString(d.Name)))
		sb.WriteString(`<span style="display:flex;gap:4px">`)
		sb.WriteString(fmt.Sprintf(`<span style="width:6px;height:6px;border-radius:50%%;background:%s" title="present"></span>`, dotPresent))
		sb.WriteString(fmt.Sprintf(`<span style="width:6px;height:6px;border-radius:50%%;background:%s" title="configured"></span>`, dotConfigured))
		sb.WriteString(fmt.Sprintf(`<span style="width:6px;height:6px;border-radius:50%%;background:%s" title="healthy"></span>`, dotHealthy))
		sb.WriteString(`</span>`)
		sb.WriteString(`</div>`)
		if detail != "" {
			sb.WriteString(fmt.Sprintf(`<div style="font:500 10px 'JetBrains Mono',monospace;color:#6b7184;margin-top:5px">%s</div>`, html.EscapeString(detail)))
		}
		sb.WriteString(`</div>`)
	}
	sb.WriteString(`</div>`) // grid
	sb.WriteString(`</div>`) // section
	return sb.String()
}

func dotColor(ok bool) string {
	if ok {
		return "#4cc79a"
	}
	return "#f5921e"
}

func subsystemDetail(d detect.Result) string {
	if note, ok := d.Details["mode"]; ok && note != "" {
		return note
	}
	if note, ok := d.Details["events_exist"]; ok {
		if note == "missing" {
			return "events pending"
		}
	}
	return ""
}

func renderV2HealthChecks(checks []health.Check, total, greenCount int) string {
	var sb strings.Builder
	sb.WriteString(`<div style="padding:16px 18px">`)
	sb.WriteString(`<div style="display:flex;align-items:center;margin-bottom:12px">`)
	sb.WriteString(`<span style="font:700 11px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase">Health checks</span>`)
	sb.WriteString(fmt.Sprintf(`<span style="font:600 11px 'JetBrains Mono',monospace;color:#54c79a;margin-left:8px">%d / %d passing</span>`, greenCount, total))
	sb.WriteString(`<span style="flex:1"></span>`)
	sb.WriteString(`<a href="/health" style="font:500 11px 'Hanken Grotesk',sans-serif;color:#7c6cf2;text-decoration:none">Full report →</a>`)
	sb.WriteString(`</div>`)
	sb.WriteString(`<div style="display:flex;flex-wrap:wrap;gap:7px">`)
	for _, c := range checks {
		dot := "#4cc79a"
		if c.Status == health.Yellow {
			dot = "#f5921e"
		} else if c.Status == health.Red {
			dot = "#ef5f6b"
		}
		label := c.Name
		// Append short value if it's a disk/number check
		if strings.Contains(c.Reason, "%") {
			for _, w := range strings.Fields(c.Reason) {
				if strings.HasSuffix(w, "%") {
					label += " " + w
					break
				}
			}
		}
		sb.WriteString(fmt.Sprintf(
			`<span style="display:inline-flex;align-items:center;gap:6px;font:500 11px 'JetBrains Mono',monospace;color:#aab0c2;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);padding:4px 9px;border-radius:6px" title="%s"><span style="width:6px;height:6px;border-radius:50%%;background:%s"></span>%s</span>`,
			html.EscapeString(c.Reason), dot, html.EscapeString(label),
		))
	}
	sb.WriteString(`</div>`)
	sb.WriteString(`</div>`) // section
	return sb.String()
}

func fmtCount(n int) string {
	if n == 0 {
		return "0"
	}
	// Simple comma-formatting
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}
