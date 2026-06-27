package ui

import (
	"fmt"
	"html"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/security/audit"
)

// handleV2Timeline renders the Live Tail timeline page.
func (s *Server) handleV2Timeline(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()

	query := strings.TrimSpace(r.URL.Query().Get("q"))
	from := strings.TrimSpace(r.URL.Query().Get("from"))
	to := strings.TrimSpace(r.URL.Query().Get("to"))
	events := s.allTimelineEvents(ctx)
	events = v2FilterTimelineEvents(events, query, from, to)

	csrf := s.csrfTokenFromRequest(r)
	_, _ = fmt.Fprint(w, v2Page("Timeline", "/v2/timeline", renderV2TimelinePage(events, query, csrf)))
}

func renderV2TimelinePage(events []audit.TimelineEvent, query, csrfToken string) string {
	histogram := renderV2TimelineHistogram(events)
	stream := renderV2TimelineStream(events, query)
	csrfEl := fmt.Sprintf(`<span id="v2-csrf-token" data-token="%s" style="display:none" aria-hidden="true"></span>`, html.EscapeString(csrfToken))

	activeFilter := ""
	if query != "" {
		activeFilter = fmt.Sprintf(
			`<span style="display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;background:rgba(251,146,60,.12);border:1px solid rgba(251,146,60,.25);font:500 11px 'JetBrains Mono',monospace;color:#fb923c">%s <a href="/v2/timeline" style="color:#fb923c;text-decoration:none;margin-left:3px">×</a></span>`,
			html.EscapeString(query),
		)
	}

	return `<style>
.tl-topbar{display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.tl-search{display:flex;align-items:center;gap:6px;flex:1;min-width:200px;background:#10121a;border:1px solid #1f2330;border-radius:8px;padding:6px 12px}
.tl-search input{background:none;border:none;outline:none;color:#e8eaf1;font:400 13px 'JetBrains Mono',monospace;flex:1;min-width:60px}
.tl-search input::placeholder{color:#4b5166}
.tl-live-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:20px;background:rgba(76,199,154,.08);border:1px solid rgba(76,199,154,.22);font:600 10px 'JetBrains Mono',monospace;color:#4cc79a}
.tl-live-dot{width:6px;height:6px;border-radius:50%;background:#4cc79a;animation:livepulse 1.8s infinite;flex-shrink:0}
.tl-histogram{display:flex;align-items:flex-end;gap:2px;height:74px}
.tl-bar{flex:1;border-radius:2px 2px 0 0;min-height:3px}
.tl-bar:hover{opacity:.7;cursor:pointer}
.tl-col-header{display:grid;grid-template-columns:150px 120px 1fr;gap:8px;padding:6px 16px;border-bottom:1px solid #1a1e29}
.tl-col-header span{font:600 10px 'JetBrains Mono',monospace;color:#4b5166;letter-spacing:.06em;text-transform:uppercase}
.tl-row{display:grid;grid-template-columns:150px 120px 1fr;gap:8px;padding:8px 16px;border-left:2px solid transparent;transition:background .1s}
.tl-row:hover{background:rgba(255,255,255,.022)}
.tl-row details{grid-column:1/-1}
.tl-row summary{cursor:pointer;color:#7c6cf2;font:600 11px 'Hanken Grotesk',sans-serif;margin-top:6px}
.tl-row-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.tl-row-actions a{font:600 11px 'Hanken Grotesk',sans-serif;color:#c5cad8;text-decoration:none;border:1px solid #20242f;background:#10121a;border-radius:7px;padding:5px 8px}
.tl-row-warn{border-left-color:#f59e0b}
.tl-row-error{border-left-color:#ef4444}
.tl-ts{font:400 11px 'JetBrains Mono',monospace;color:#6b7184;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;align-self:center}
.tl-src{align-self:center}
.tl-pills{display:flex;align-items:center;gap:5px;flex-wrap:wrap;align-self:center}
.tl-pill{display:inline-flex;align-items:center;padding:2px 7px;border-radius:5px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);font:500 11px 'JetBrains Mono',monospace;color:#cdd2e0;white-space:nowrap}
.tl-pill-warn{background:rgba(251,146,60,.08);border-color:rgba(251,146,60,.2);color:#fb923c}
.tl-pill-error{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.2);color:#f87171}
.tl-pill-corr{background:rgba(124,108,242,.10);border-color:rgba(124,108,242,.25);color:#9b8cff}
.tl-pill-src{display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:5px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);font:600 11px 'JetBrains Mono',monospace;color:#cdd2e0}
.tl-pill-key{color:#787f93}
.tl-empty{padding:40px 16px;text-align:center;font:400 13px 'JetBrains Mono',monospace;color:#4b5166}
.tl-more{padding:10px 16px;text-align:center;font:400 11px 'JetBrains Mono',monospace;color:#4b5166;border-top:1px solid #1a1e29}
</style>

<div class="tl-topbar">
  <span style="font:700 18px 'Hanken Grotesk',sans-serif;color:#eef0f6;flex-shrink:0">Timeline</span>
  <form method="get" action="/v2/timeline" class="tl-search">
    <span style="color:#4b5166;font-size:14px">⌕</span>
    <input type="text" name="q" placeholder="filter by IP, action, source…" value="` + html.EscapeString(query) + `">
  </form>
  ` + activeFilter + `
  <span class="tl-live-badge"><span class="tl-live-dot"></span>LIVE</span>
</div>

<div style="background:#10121a;border:1px solid #1a1e29;border-radius:8px;padding:10px 14px;margin-bottom:14px">
  <div class="tl-histogram">` + histogram + `</div>
</div>

<div style="background:#10121a;border:1px solid #1a1e29;border-radius:8px;overflow:hidden">
  <div class="tl-col-header">
    <span>Time</span>
    <span>Source</span>
    <span>Event</span>
  </div>
  ` + stream + `
</div>
` + csrfEl
}

func renderV2TimelineHistogram(events []audit.TimelineEvent) string {
	const buckets = 46
	const windowH = 24

	now := time.Now()
	bucketDur := time.Duration(windowH) * time.Hour / buckets
	counts := make([]int, buckets)
	warnCounts := make([]int, buckets)

	for _, ev := range events {
		t, err := time.Parse(time.RFC3339, ev.Timestamp)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04:05", ev.Timestamp)
			if err != nil {
				continue
			}
		}
		ago := now.Sub(t)
		if ago < 0 || ago > time.Duration(windowH)*time.Hour {
			continue
		}
		idx := int(ago / bucketDur)
		if idx >= buckets {
			idx = buckets - 1
		}
		ridx := buckets - 1 - idx // reverse so recent events are on the right
		counts[ridx]++
		sev := strings.ToLower(ev.Severity)
		if sev == "warning" || sev == "warn" || sev == "suppressed" {
			warnCounts[ridx]++
		}
	}

	maxCount := 1
	for _, c := range counts {
		if c > maxCount {
			maxCount = c
		}
	}

	var sb strings.Builder
	for i := 0; i < buckets; i++ {
		count := counts[i]
		warnCount := warnCounts[i]

		var heightPct float64
		if count == 0 {
			// Aesthetic baseline so empty state still looks like a histogram
			heightPct = 0.04 + 0.08*math.Abs(math.Sin(float64(i)*0.71+1.3))
		} else {
			heightPct = float64(count) / float64(maxCount)
		}
		height := int(4 + heightPct*66)

		var color string
		if count == 0 {
			color = "rgba(100,110,135,.22)"
		} else if warnCount > 0 && warnCount*2 >= count {
			color = "rgba(251,146,60,.65)"
		} else if count > maxCount/3 {
			color = "rgba(124,108,242,.70)"
		} else {
			color = "rgba(100,130,180,.45)"
		}

		// Bucket i covers: [now - (buckets-i)*bucketDur, now - (buckets-i-1)*bucketDur)
		fromTs := now.Add(-time.Duration(buckets-i) * bucketDur).Unix()
		toTs := now.Add(-time.Duration(buckets-i-1) * bucketDur).Unix()
		href := fmt.Sprintf("/v2/timeline?from=%d&to=%d", fromTs, toTs)

		sb.WriteString(fmt.Sprintf(
			`<a href="%s" class="tl-bar" style="height:%dpx;background:%s;display:block;text-decoration:none" title="%d events — click to filter"></a>`,
			html.EscapeString(href), height, color, count,
		))
	}
	return sb.String()
}

func renderV2TimelineStream(events []audit.TimelineEvent, query string) string {
	if len(events) == 0 {
		msg := "No investigation started."
		if query != "" {
			msg = "No matching timeline events."
		}
		return `<div class="tl-empty"><div style="font:700 16px 'Hanken Grotesk',sans-serif;color:#c5cad8;margin-bottom:5px">` + html.EscapeString(msg) + `</div><div style="font:500 12px 'Hanken Grotesk',sans-serif;color:#6b7184">Recent activity and suggested pivots stay available even before data arrives.</div><div class="v2-empty-actions" style="max-width:860px;margin:16px auto 0">
<a class="v2-empty-action" href="/v2/investigate">Search IP <span>›</span></a>
<a class="v2-empty-action" href="/v2/timeline">Browse Timeline <span>›</span></a>
<a class="v2-empty-action" href="/v2/investigate">Recent Evidence <span>›</span></a>
<a class="v2-empty-action" href="/v2/timeline?q=waf">Recent WAF Events <span>›</span></a>
<a class="v2-empty-action" href="/v2/timeline?q=abuseipdb">Recent AbuseIPDB Reports <span>›</span></a>
</div><div style="font:700 10px 'JetBrains Mono',monospace;letter-spacing:.12em;text-transform:uppercase;color:#52596d;margin-top:18px">Quick actions</div></div>`
	}

	const limit = 200
	var sb strings.Builder
	shown := len(events)
	if shown > limit {
		shown = limit
	}
	for i := 0; i < shown; i++ {
		sb.WriteString(renderV2TimelineRow(events[i]))
	}
	if len(events) > limit {
		sb.WriteString(fmt.Sprintf(
			`<div class="tl-more">Showing %d of %d events — use the search bar to narrow results.</div>`,
			limit, len(events),
		))
	}
	return sb.String()
}

func renderV2TimelineRow(ev audit.TimelineEvent) string {
	sev := strings.ToLower(ev.Severity)
	rowClass := "tl-row"
	switch sev {
	case "error", "critical":
		rowClass += " tl-row-error"
	case "warning", "warn", "suppressed":
		rowClass += " tl-row-warn"
	}

	ts := ev.Timestamp
	if len(ts) >= 19 {
		ts = ts[11:19] // HH:MM:SS
	}

	return fmt.Sprintf(
		`<div class="%s"><span class="tl-ts">%s</span><div class="tl-src">%s</div><div class="tl-pills">%s</div>%s</div>`,
		rowClass,
		html.EscapeString(ts),
		v2TimelineSourcePill(ev.ActorSource),
		v2TimelinePrimaryPills(ev),
		v2TimelineRowDetails(ev),
	)
}

func v2TimelineSourcePill(source string) string {
	dotColor := "#6b7280"
	src := strings.ToLower(source)
	switch {
	case strings.Contains(src, "nginx"):
		dotColor = "#3b82f6"
	case strings.Contains(src, "waf") || strings.Contains(src, "cf"):
		dotColor = "#f97316"
	case src == "ui" || src == "system" || src == "daemon":
		dotColor = "#7c6cf2"
	}
	label := source
	if label == "" {
		label = "unknown"
	}
	return fmt.Sprintf(
		`<span class="tl-pill-src"><span style="width:5px;height:5px;border-radius:50%%;background:%s;display:inline-block;flex-shrink:0"></span>%s</span>`,
		dotColor, html.EscapeString(label),
	)
}

// v2TimelinePrimaryPills renders the always-visible pills: action + ip.
// Secondary detail (result, summary, correlation, evidence) is moved into the
// expandable details element by v2TimelineRowDetails so the feed stays compact.
func v2TimelinePrimaryPills(ev audit.TimelineEvent) string {
	var parts []string

	if ev.Action != "" {
		parts = append(parts, v2TimelineKVPill("action", ev.Action, ""))
	}

	if ev.Target != "" {
		parts = append(parts, fmt.Sprintf(
			`<a href="/v2/investigate?q=%s" style="text-decoration:none"><span class="tl-pill"><span class="tl-pill-key">ip:</span>%s</span></a>`,
			url.QueryEscape(ev.Target), html.EscapeString(ev.Target),
		))
	}

	return strings.Join(parts, "")
}

// v2TimelineSecondaryPills renders result, summary, correlation and evidence
// pills that are shown only inside the details expansion.
func v2TimelineSecondaryPills(ev audit.TimelineEvent) string {
	var parts []string

	if ev.Result != "" {
		sev := ""
		r := strings.ToLower(ev.Result)
		if strings.Contains(r, "ban") || strings.Contains(r, "block") || strings.Contains(r, "deny") {
			sev = "error"
		} else if strings.Contains(r, "warn") || strings.Contains(r, "monitor") {
			sev = "warn"
		}
		parts = append(parts, v2TimelineKVPill("result", ev.Result, sev))
	}

	if ev.Summary != "" {
		parts = append(parts, fmt.Sprintf(
			`<span style="font:400 12px 'Hanken Grotesk',sans-serif;color:#9aa0b2">%s</span>`,
			html.EscapeString(ev.Summary),
		))
	}

	if ev.CorrelationID != "" {
		short := ev.CorrelationID
		if len(short) > 10 {
			short = short[:10]
		}
		parts = append(parts, fmt.Sprintf(
			`<span class="tl-pill tl-pill-corr"><span class="tl-pill-key">corr:</span>%s</span>`,
			html.EscapeString(short),
		))
	}

	if ev.EvidenceID != "" {
		short := ev.EvidenceID
		if len(short) > 10 {
			short = short[:10]
		}
		parts = append(parts, fmt.Sprintf(
			`<span class="tl-pill tl-pill-corr"><span class="tl-pill-key">ev:</span>%s</span>`,
			html.EscapeString(short),
		))
	}

	return strings.Join(parts, "")
}

func v2TimelineRowDetails(ev audit.TimelineEvent) string {
	secondary := v2TimelineSecondaryPills(ev)
	hasTarget := ev.Target != ""
	hasSecondary := secondary != ""

	if !hasTarget && ev.EvidenceID == "" && ev.CorrelationID == "" && !hasSecondary {
		return ""
	}

	var actions []string
	if hasTarget {
		q := url.QueryEscape(ev.Target)
		actions = append(actions,
			fmt.Sprintf(`<a href="/v2/incident?ip=%s">Focus Incident</a>`, q),
			fmt.Sprintf(`<a href="/v2/investigate?q=%s">Investigate</a>`, q),
			fmt.Sprintf(`<a href="/v2/timeline?q=%s">Timeline filtered</a>`, q),
			fmt.Sprintf(`<a href="https://www.abuseipdb.com/check/%s" target="_blank" rel="noopener noreferrer">AbuseIPDB ↗</a>`, q),
			fmt.Sprintf(`<a href="https://www.virustotal.com/gui/ip-address/%s" target="_blank" rel="noopener noreferrer">VirusTotal ↗</a>`, q),
		)
	}

	secondarySection := ""
	if hasSecondary {
		secondarySection = fmt.Sprintf(`<div class="tl-pills" style="margin-top:6px">%s</div>`, secondary)
	}
	actionsSection := ""
	if len(actions) > 0 {
		actionsSection = fmt.Sprintf(`<div class="tl-row-actions">%s</div>`, strings.Join(actions, ""))
	}
	whySection := v2TimelineWhyItMatters(ev.Action)

	// ✦ AI explain trigger for this event
	aiTrigger := ""
	if ev.Target != "" {
		summary := ev.Action
		if ev.Summary != "" {
			summary = ev.Summary
		}
		aiTrigger = fmt.Sprintf(
			`<button type="button" data-ai-explain-trigger data-ai-subject-type="event" data-ai-subject-id="%s" data-ai-summary="%s" title="Ask AI" style="background:none;border:none;cursor:pointer;font-size:13px;color:#9b8cff;padding:2px 5px;border-radius:4px;line-height:1;opacity:.7;margin-left:auto;flex-shrink:0" onmouseover="this.style.opacity=1" onmouseout="this.style.opacity=.7">✦</button>`,
			html.EscapeString(ev.Target),
			html.EscapeString(summary),
		)
	}

	return fmt.Sprintf(`<details><summary>row details%s</summary>%s%s%s</details>`, aiTrigger, secondarySection, actionsSection, whySection)
}

func v2TimelineKVPill(key, value, sev string) string {
	cls := "tl-pill"
	switch sev {
	case "warn":
		cls += " tl-pill-warn"
	case "error":
		cls += " tl-pill-error"
	}
	return fmt.Sprintf(
		`<span class="%s"><span class="tl-pill-key">%s:</span>%s</span>`,
		cls, html.EscapeString(key), html.EscapeString(value),
	)
}

// v2TimelineWhyItMatters returns a contextual guidance line based on the event action.
func v2TimelineWhyItMatters(action string) string {
	a := strings.ToLower(action)
	switch {
	case strings.Contains(a, "malicious") || strings.Contains(a, "ban") || strings.Contains(a, "block"):
		return `<div style="font:500 12px 'Hanken Grotesk',sans-serif;color:#9aa0b2;margin-top:8px;padding:6px 8px;border-radius:6px;border-left:2px solid #ef5f6b">High confidence threat. Consider reviewing correlated events if multiple IPs share the same ASN.</div>`
	case strings.Contains(a, "suspicious") || strings.Contains(a, "flag") || strings.Contains(a, "suppress"):
		return `<div style="font:500 12px 'Hanken Grotesk',sans-serif;color:#9aa0b2;margin-top:8px;padding:6px 8px;border-radius:6px;border-left:2px solid #f5a443">Borderline signal — monitor this source. Review AbuseIPDB score if persistent.</div>`
	case strings.Contains(a, "whitelist") || strings.Contains(a, "trust") || strings.Contains(a, "allow"):
		return `<div style="font:500 12px 'Hanken Grotesk',sans-serif;color:#9aa0b2;margin-top:8px;padding:6px 8px;border-radius:6px;border-left:2px solid #9b8cff">Operator-trusted source. This event will not trigger enforcement.</div>`
	}
	return ""
}

// v2FilterTimelineEvents filters events by query text and optional unix-timestamp from/to range.
func v2FilterTimelineEvents(events []audit.TimelineEvent, query, from, to string) []audit.TimelineEvent {
	var fromT, toT time.Time
	if fromUnix, err := strconv.ParseInt(from, 10, 64); err == nil && fromUnix > 0 {
		fromT = time.Unix(fromUnix, 0)
	}
	if toUnix, err := strconv.ParseInt(to, 10, 64); err == nil && toUnix > 0 {
		toT = time.Unix(toUnix, 0)
	}

	q := strings.ToLower(strings.TrimSpace(query))
	hasTimeFilter := !fromT.IsZero() || !toT.IsZero()
	if q == "" && !hasTimeFilter {
		return events
	}

	out := make([]audit.TimelineEvent, 0, len(events))
	for _, ev := range events {
		if q != "" && !timelineMatchesQuery(ev, q) {
			continue
		}
		if hasTimeFilter {
			var t time.Time
			var err error
			t, err = time.Parse(time.RFC3339, ev.Timestamp)
			if err != nil {
				t, err = time.Parse("2006-01-02T15:04:05", ev.Timestamp)
			}
			if err != nil {
				continue
			}
			if !fromT.IsZero() && t.Before(fromT) {
				continue
			}
			if !toT.IsZero() && t.After(toT) {
				continue
			}
		}
		out = append(out, ev)
	}
	return out
}
