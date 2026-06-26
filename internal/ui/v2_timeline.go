package ui

import (
	"fmt"
	"html"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/security/audit"
)

// handleV2Timeline renders the Live Tail timeline page.
func (s *Server) handleV2Timeline(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()

	query := strings.TrimSpace(r.URL.Query().Get("q"))
	events := s.allTimelineEvents(ctx)
	if query != "" {
		events = filterTimelineEvents(events, query, "", "")
	}

	_, _ = fmt.Fprint(w, v2Page("Timeline", "/v2/timeline", renderV2TimelinePage(events, query)))
}

func renderV2TimelinePage(events []audit.TimelineEvent, query string) string {
	histogram := renderV2TimelineHistogram(events)
	stream := renderV2TimelineStream(events, query)

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
</div>`
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

		sb.WriteString(fmt.Sprintf(
			`<div class="tl-bar" style="height:%dpx;background:%s" title="%d events in bucket"></div>`,
			height, color, count,
		))
	}
	return sb.String()
}

func renderV2TimelineStream(events []audit.TimelineEvent, query string) string {
	if len(events) == 0 {
		msg := "No timeline events yet."
		if query != "" {
			msg = "No events match the filter."
		}
		return `<div class="tl-empty">` + html.EscapeString(msg) + `</div>`
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
		`<div class="%s"><span class="tl-ts">%s</span><div class="tl-src">%s</div><div class="tl-pills">%s</div></div>`,
		rowClass,
		html.EscapeString(ts),
		v2TimelineSourcePill(ev.ActorSource),
		v2TimelinePills(ev),
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

func v2TimelinePills(ev audit.TimelineEvent) string {
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
