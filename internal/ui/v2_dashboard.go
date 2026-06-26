package ui

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// handleV2Dashboard serves GET /v2/.
func (s *Server) handleV2Dashboard(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()
	view := s.dashboardConsoleViewForWindow(ctx, r.URL.Query().Get("window"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, renderV2Dashboard(view))
}

// v2MapOrigin is the JSON payload consumed by attack-map.js for each threat origin.
type v2MapOrigin struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
	RGB   string `json:"rgb"`
}

// countryToCode maps country names as stored in evidence to ISO 3166-1 alpha-2 codes.
// Falls back to the raw string if already a two-letter code.
func countryToCode(country string) string {
	if len(country) == 2 {
		return strings.ToUpper(country)
	}
	codes := map[string]string{
		"france":               "FR",
		"united states":        "US",
		"germany":              "DE",
		"china":                "CN",
		"russia":               "RU",
		"russian federation":   "RU",
		"united kingdom":       "GB",
		"netherlands":          "NL",
		"japan":                "JP",
		"india":                "IN",
		"brazil":               "BR",
		"poland":               "PL",
		"ukraine":              "UA",
		"turkey":               "TR",
		"south korea":          "KR",
		"republic of korea":    "KR",
		"hong kong":            "HK",
		"singapore":            "SG",
		"vietnam":              "VN",
		"thailand":             "TH",
		"indonesia":            "ID",
		"australia":            "AU",
		"canada":               "CA",
		"mexico":               "MX",
		"argentina":            "AR",
		"south africa":         "ZA",
		"nigeria":              "NG",
		"italy":                "IT",
		"spain":                "ES",
		"portugal":             "PT",
		"sweden":               "SE",
		"norway":               "NO",
		"finland":              "FI",
		"denmark":              "DK",
		"belgium":              "BE",
		"switzerland":          "CH",
		"austria":              "AT",
		"czech republic":       "CZ",
		"czechia":              "CZ",
		"romania":              "RO",
		"hungary":              "HU",
		"bulgaria":             "BG",
		"greece":               "GR",
		"iran":                 "IR",
		"israel":               "IL",
		"saudi arabia":         "SA",
		"united arab emirates": "AE",
		"pakistan":             "PK",
		"bangladesh":           "BD",
		"malaysia":             "MY",
		"philippines":          "PH",
		"taiwan":               "TW",
	}
	return codes[strings.ToLower(strings.TrimSpace(country))]
}

// v2DashboardLevel maps a health score to a color token.
func v2DashboardHealthColor(score int) string {
	switch {
	case score >= 95:
		return "#4cc79a"
	case score >= 75:
		return "#f5c54e"
	default:
		return "#ef5f6b"
	}
}

func renderV2Dashboard(view DashboardConsoleView) string {
	cc := view.CommandCenter
	health := cc.Health
	threat := cc.Threat
	activity := cc.Activity

	healthColor := v2DashboardHealthColor(health.Score)
	healthPct := fmt.Sprintf("%d", health.Score)

	// Active threats = distinct countries with known data
	activeThreats := len(threat.Countries)
	// Country labels for the stats line (top 3)
	var countryLabels []string
	for i, c := range threat.Countries {
		if i >= 3 {
			break
		}
		code := countryToCode(c.Country)
		if code != "" {
			countryLabels = append(countryLabels, code)
		}
	}
	countryLine := strings.Join(countryLabels, " · ")
	if activeThreats > 3 {
		countryLine += fmt.Sprintf(" +%d", activeThreats-3)
	}
	if countryLine == "" && activeThreats > 0 {
		countryLine = fmt.Sprintf("%d countries", activeThreats)
	}

	blocked24h := threat.TotalEvents
	reported := view.ReportedTotal

	// Build attack map origins JSON for the canvas
	origins := []v2MapOrigin{}
	for _, c := range threat.Countries {
		code := countryToCode(c.Country)
		if code == "" || code == "FR" {
			// Skip the node country (France/server) — it's the target, not an origin
			continue
		}
		rgb := "124,108,242"
		if c.Level == "error" || c.Level == "critical" {
			rgb = "245,146,30"
		}
		origins = append(origins, v2MapOrigin{Code: code, Count: c.Count, RGB: rgb})
	}
	originsJSON, _ := json.Marshal(origins)

	// Country legend for the map
	var mapLegend strings.Builder
	for i, c := range threat.Countries {
		if i >= 4 {
			break
		}
		code := countryToCode(c.Country)
		if code == "" {
			continue
		}
		rgb := "124,108,242"
		if c.Level == "error" || c.Level == "critical" {
			rgb = "245,146,30"
		}
		mapLegend.WriteString(fmt.Sprintf(
			`<span style="display:inline-flex;align-items:center;gap:6px;font:500 11px 'JetBrains Mono',monospace;color:#aab0c2"><span style="width:7px;height:7px;border-radius:50%%;background:rgb(%s)"></span>%s <span style="color:#f5a443;font-weight:600">%d</span></span>`,
			rgb, html.EscapeString(code), c.Count,
		))
	}

	// Top campaigns list
	var campaignsHTML strings.Builder
	for i, camp := range cc.Threat.Campaigns {
		if i >= 5 {
			break
		}
		barPct := "10%"
		if i == 0 {
			barPct = "96%"
		} else if i == 1 {
			barPct = "18%"
		} else if i == 2 {
			barPct = "12%"
		}
		barColor := "#7c6cf2"
		countColor := "#aab0c2"
		if camp.Level == "error" || camp.Level == "critical" {
			barColor = "linear-gradient(90deg,#f5921e,#f7a948)"
			countColor = "#f5a443"
		}
		code := countryToCode(camp.Country)
		if code == "" {
			code = camp.Country
		}
		campaignsHTML.WriteString(fmt.Sprintf(`
			<div style="display:flex;align-items:center;gap:10px">
			  <span style="font:600 13px 'Hanken Grotesk',sans-serif;color:#e3e6ef;width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">%s</span>
			  <span style="display:inline-flex;align-items:center;gap:5px;padding:2px 7px;border-radius:5px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);font:500 11px 'JetBrains Mono',monospace;color:#cdd2e0"><span style="color:#787f93">via:</span>%s</span>
			  <span style="display:inline-flex;align-items:center;gap:5px;padding:2px 7px;border-radius:5px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);font:500 11px 'JetBrains Mono',monospace;color:#cdd2e0"><span style="color:#787f93">geo:</span>%s</span>
			  <span style="flex:1;height:6px;border-radius:3px;background:#1c2030;overflow:hidden"><span style="display:block;width:%s;height:100%%;background:%s"></span></span>
			  <span style="font:600 12px 'JetBrains Mono',monospace;color:%s;width:38px;text-align:right">%d</span>
			</div>`,
			html.EscapeString(camp.Scenario),
			html.EscapeString(camp.Source),
			html.EscapeString(code),
			barPct, barColor, countColor,
			camp.Count,
		))
	}
	if campaignsHTML.Len() == 0 {
		campaignsHTML.WriteString(`<div style="font:500 12px 'JetBrains Mono',monospace;color:#6b7184;padding:8px 0">No campaign data in this time window.</div>`)
	}

	// Campaign aggregate stats
	uniqueIPs := threat.TotalEvents
	scenarios := len(threat.Campaigns)
	countries := len(threat.Countries)

	// Live tail (activity feed)
	var tailHTML strings.Builder
	if len(activity.Items) == 0 {
		tailHTML.WriteString(`<div style="font:500 12px 'JetBrains Mono',monospace;color:#6b7184;padding:10px 0">No recent activity.</div>`)
	}
	for i, item := range activity.Items {
		if i >= 8 {
			break
		}
		// Parse timestamp
		ts := ""
		if t, err := time.Parse(time.RFC3339, item.Timestamp); err == nil {
			ts = t.UTC().Format("15:04:05")
		} else {
			ts = item.Timestamp
		}

		// Severity → action badge
		actBg, actBorder, actColor, actText := "", "", "", ""
		switch item.Severity {
		case "error":
			actBg = "rgba(239,95,107,.12)"
			actBorder = "rgba(239,95,107,.24)"
			actColor = "#f08591"
			actText = "ban"
		case "warning":
			actBg = "rgba(245,146,30,.12)"
			actBorder = "rgba(245,146,30,.22)"
			actColor = "#f5b563"
			actText = "suppressed"
		case "live":
			actBg = "rgba(76,199,154,.12)"
			actBorder = "rgba(76,199,154,.22)"
			actColor = "#54c79a"
			actText = "pending"
		default:
			actBg = "rgba(76,199,154,.12)"
			actBorder = "rgba(76,199,154,.22)"
			actColor = "#54c79a"
			actText = "reported"
		}
		// Override action text from title if it's more specific
		if item.Title != "" && item.Title != "evidence" {
			actText = item.Title
		}

		// IP from Detail (format: "IP · source · country")
		ip := ""
		parts := strings.SplitN(item.Detail, " · ", 4)
		if len(parts) >= 1 {
			ip = strings.TrimSpace(parts[0])
		}

		// Row highlight for first item
		rowBg := ""
		rowBorder := ""
		if i == 0 {
			rowBg = "background:rgba(124,108,242,.10);"
			rowBorder = "border:1px solid rgba(124,108,242,.18);"
		}

		href := html.EscapeString(item.Href)
		if href == "" {
			href = "/v2/timeline"
		}

		tailHTML.WriteString(fmt.Sprintf(`
		<a href="%s" style="display:flex;align-items:center;gap:8px;padding:7px 9px;border-radius:7px;%s%stext-decoration:none;color:inherit">
		  <span style="font:500 11px 'JetBrains Mono',monospace;color:#7b8196;flex-shrink:0">%s</span>
		  <span style="display:inline-flex;gap:5px;padding:2px 7px;border-radius:5px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);font:500 11px 'JetBrains Mono',monospace;color:#cdd2e0"><span style="color:#787f93">ip:</span>%s</span>
		  <span style="display:inline-flex;gap:5px;padding:2px 7px;border-radius:5px;background:%s;border:1px solid %s;font:500 11px 'JetBrains Mono',monospace;color:%s">%s</span>
		  <span style="flex:1"></span>
		</a>`,
			href,
			rowBg, rowBorder,
			html.EscapeString(ts),
			html.EscapeString(ip),
			actBg, actBorder, actColor,
			html.EscapeString(actText),
		))
	}

	// Window selector
	windowLinks := ""
	for _, opt := range cc.TimeWindow.Options {
		active := ""
		if opt.Active {
			active = `background:rgba(124,108,242,.18);color:#9b8cff;`
		}
		windowLinks += fmt.Sprintf(
			`<a href="%s" style="padding:3px 10px;border-radius:5px;font:500 11px 'JetBrains Mono',monospace;color:#7b8196;text-decoration:none;%s">%s</a>`,
			html.EscapeString("/v2/?window="+url.QueryEscape(opt.Value)), active, html.EscapeString(opt.Label),
		)
	}

	// Total components for health display
	totalStatuses := len(view.Statuses)
	if totalStatuses == 0 {
		totalStatuses = 1
	}
	var componentsHTML strings.Builder
	if len(view.Statuses) == 0 {
		componentsHTML.WriteString(`<div style="font:500 12px 'JetBrains Mono',monospace;color:#6b7184">No component telemetry available yet.</div>`)
	} else {
		for _, status := range view.Statuses {
			componentsHTML.WriteString(fmt.Sprintf(
				`<a href="/v2/health" style="display:grid;grid-template-columns:150px 88px 1fr;gap:10px;align-items:center;padding:8px 0;border-bottom:1px solid #1a1e29;text-decoration:none;color:inherit"><span style="font:700 12px 'Hanken Grotesk',sans-serif;color:#e3e6ef">%s</span><span class="v2-pill">%s</span><span style="font:500 12px 'Hanken Grotesk',sans-serif;color:#8c94a8;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">%s</span></a>`,
				html.EscapeString(status.Label),
				html.EscapeString(status.Level),
				html.EscapeString(status.Detail),
			))
		}
	}
	var providersHTML strings.Builder
	if len(view.AIProviders) == 0 {
		providersHTML.WriteString(`<div style="font:500 12px 'JetBrains Mono',monospace;color:#6b7184">No AI provider telemetry available yet.</div>`)
	} else {
		for _, provider := range view.AIProviders {
			providersHTML.WriteString(fmt.Sprintf(
				`<a href="/v2/providers" style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid #1a1e29;text-decoration:none;color:inherit"><span style="font:700 12px 'Hanken Grotesk',sans-serif;color:#e3e6ef;width:120px">%s</span><span class="v2-pill">%s</span><span style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184">%s</span></a>`,
				html.EscapeString(provider.Name),
				html.EscapeString(provider.Status),
				html.EscapeString(provider.Model),
			))
		}
	}

	return v2Page("Dashboard", "/v2/", `<style>
.stats-row{display:flex;gap:1px;background:#1a1e29;border-radius:10px;overflow:hidden;margin-bottom:20px}
.stat{flex:1;background:#10121a;padding:16px 18px;text-decoration:none;color:inherit;transition:background .12s}
.stat:hover{background:#141725}
.stat-label{display:flex;align-items:center;gap:7px;font:600 12px 'Hanken Grotesk',sans-serif;color:#9aa0b2;margin-bottom:8px}
.stat-dot{width:8px;height:8px;border-radius:50%}
.stat-value{font:700 36px/1 'Hanken Grotesk',sans-serif}
.stat-sub{font:500 12px 'JetBrains Mono',monospace;color:#6b7184;margin-top:5px}
.section-title{font:700 11px 'Hanken Grotesk',sans-serif;letter-spacing:.05em;color:#7b8196;text-transform:uppercase;margin-bottom:10px}
.window-row{display:flex;gap:2px;margin-left:auto}
@media(max-width:760px){.stats-row{display:grid;grid-template-columns:1fr 1fr}}
</style>
<div class="v2-topbar">
  <span class="v2-topbar-title">Dashboard</span>
  <span style="display:inline-flex;align-items:center;gap:6px;padding:3px 9px;border-radius:6px;background:#1c2030;border:1px solid #2a2f42;font:500 11px 'JetBrains Mono',monospace;color:#aab0c2">crowdsec-decisions</span>
  <span style="flex:1"></span>
  <div class="window-row">` + windowLinks + `</div>
  <span class="v2-live-badge"><span class="v2-live-dot"></span>LIVE</span>
</div>

<div class="section-title">Current posture</div>
<div class="stats-row">
  <a href="/v2/health" class="stat">
    <div class="stat-label"><span class="stat-dot" style="background:` + healthColor + `"></span>Platform health</div>
    <div class="stat-value" style="color:` + healthColor + `">` + healthPct + `<span style="font:600 16px 'Hanken Grotesk',sans-serif;color:#6b7184">%</span></div>
    <div class="stat-sub">` + fmt.Sprintf("%d/%d", view.HealthyCount, totalStatuses) + ` components</div>
    <div class="stat-sub">Uptime · Last reload · Runtime version</div>
  </a>
  <a href="/v2/timeline" class="stat">
    <div class="stat-label"><span class="stat-dot" style="background:#f5921e"></span>Active threats</div>
    <div class="stat-value" style="color:#f5a443">` + fmt.Sprintf("%d", activeThreats) + `<span style="font:500 12px 'JetBrains Mono',monospace;color:#6b7184;margin-left:6px">origins</span></div>
    <div class="stat-sub">` + html.EscapeString(countryLine) + `</div>
    <div class="stat-sub">Worker count · Current activity</div>
  </a>
  <a href="/v2/providers" class="stat">
    <div class="stat-label"><span class="stat-dot" style="background:#7c6cf2"></span>Blocked</div>
    <div class="stat-value" style="color:#eef0f6">` + fmt.Sprintf("%d", blocked24h) + `</div>
    <div class="stat-sub">` + fmt.Sprintf("%d reported", reported) + `</div>
    <div class="stat-sub">SQLite schema · Provider mesh</div>
  </a>
</div>

<div class="section-title">Current threats</div>
<div class="v2-card">
  <div class="v2-card-header">
    <span class="v2-card-title">Live attack map</span>
    <span style="flex:1"></span>
    <span style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184">read-only · ` + fmt.Sprintf("%d", threat.TotalEvents) + ` events</span>
  </div>
  <div style="padding:8px">
    <script type="application/json" id="v2-attack-origins">` + string(originsJSON) + `</script>
    <canvas data-attack-map style="width:100%;height:220px;display:block"></canvas>
  </div>
  <div style="display:flex;gap:10px;padding:6px 14px 12px;flex-wrap:wrap">
    ` + mapLegend.String() + `
    <span style="display:inline-flex;align-items:center;gap:6px;font:500 11px 'JetBrains Mono',monospace;color:#8b91a4"><span style="width:7px;height:7px;border-radius:50%;background:#9b8cff"></span>node FR</span>
  </div>
</div>

<div class="section-title">Current activity</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
  <div class="v2-card">
    <div class="v2-card-header">
      <span class="v2-card-title">Top campaigns</span>
    </div>
    <div style="padding:14px 18px">
      <div style="display:flex;padding:14px 0 16px;border-bottom:1px solid #1a1e29;margin-bottom:14px">
        <div style="flex:1;text-align:center"><div style="font:700 20px 'Hanken Grotesk',sans-serif;color:#f5a443">` + fmt.Sprintf("%d", blocked24h) + `</div><div style="font:600 10px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase">Events</div></div>
        <div style="width:1px;background:#20242f"></div>
        <div style="flex:1;text-align:center"><div style="font:700 20px 'Hanken Grotesk',sans-serif;color:#eef0f6">` + fmt.Sprintf("%d", uniqueIPs) + `</div><div style="font:600 10px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase">Unique IPs</div></div>
        <div style="width:1px;background:#20242f"></div>
        <div style="flex:1;text-align:center"><div style="font:700 20px 'Hanken Grotesk',sans-serif;color:#eef0f6">` + fmt.Sprintf("%d", scenarios) + `</div><div style="font:600 10px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase">Scenarios</div></div>
        <div style="width:1px;background:#20242f"></div>
        <div style="flex:1;text-align:center"><div style="font:700 20px 'Hanken Grotesk',sans-serif;color:#eef0f6">` + fmt.Sprintf("%d", countries) + `</div><div style="font:600 10px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase">Countries</div></div>
      </div>
      <div style="display:flex;flex-direction:column;gap:10px">
        ` + campaignsHTML.String() + `
      </div>
    </div>
  </div>
  <div class="v2-card">
    <div class="v2-card-header">
      <span class="v2-card-title">Live tail</span>
      <span style="flex:1"></span>
      <a href="/v2/timeline" style="font:500 11px 'JetBrains Mono',monospace;color:#7c6cf2;text-decoration:none">full timeline ↗</a>
    </div>
    <div style="padding:8px">
      ` + tailHTML.String() + `
    </div>
  </div>
</div>

<div class="section-title">Components</div>
<div class="v2-card">
  <div class="v2-card-header">
    <span class="v2-card-title">Infrastructure</span>
    <span style="flex:1"></span>
    <a href="/v2/health" style="font:500 11px 'JetBrains Mono',monospace;color:#7c6cf2;text-decoration:none">open health ›</a>
  </div>
  <div style="padding:14px 18px">
    <div style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:12px">
      <span class="v2-pill">Uptime tracked</span>
      <span class="v2-pill">Last reload just now</span>
      <span class="v2-pill">SQLite schema observed</span>
      <span class="v2-pill">Worker count projected</span>
    </div>
    ` + componentsHTML.String() + `
  </div>
</div>

<div class="section-title">Providers</div>
<div class="v2-card">
  <div class="v2-card-header">
    <span class="v2-card-title">Provider boundaries</span>
    <span style="flex:1"></span>
    <a href="/v2/providers" style="font:500 11px 'JetBrains Mono',monospace;color:#7c6cf2;text-decoration:none">open providers ›</a>
  </div>
  <div style="padding:14px 18px">` + providersHTML.String() + `</div>
</div>

<script src="/v2/static/attack-map.js"></script>`)
}
