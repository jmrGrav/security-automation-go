package ui

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/security/audit"
)

type TimelineView struct {
	Query     string
	Action    string
	Page      int
	PageSize  int
	Total     int
	HasPrev   bool
	HasNext   bool
	EmptyText string
	Entries   []audit.TimelineEvent
	Badges    []StatusItem
}

func (s *Server) timelineView(r *http.Request) TimelineView {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	page := parsePositiveInt(r.URL.Query().Get("page"), 1)
	pageSize := clampInt(parsePositiveInt(r.URL.Query().Get("limit"), 20), 5, 100)

	events := s.timelineEvents()
	events = filterTimelineEvents(events, query, action)
	total := len(events)
	paged, hasPrev, hasNext := paginateTimelineEvents(events, page, pageSize)

	badges := []StatusItem{
		{Label: "Events", Level: "healthy", Detail: strconv.Itoa(total)},
		{Label: "Page", Level: "live", Detail: fmt.Sprintf("%d / %d", page, maxInt(1, (total+pageSize-1)/pageSize))},
	}
	if query != "" {
		badges = append(badges, StatusItem{Label: "Search", Level: "warning", Detail: query})
	}
	if action != "" {
		badges = append(badges, StatusItem{Label: "Action filter", Level: "warning", Detail: action})
	}

	emptyText := "No timeline events yet. Audit entries and operator lookups will appear here when they are recorded."
	if query != "" || action != "" {
		emptyText = "No matching timeline events."
	}

	return TimelineView{
		Query:     query,
		Action:    action,
		Page:      page,
		PageSize:  pageSize,
		Total:     total,
		HasPrev:   hasPrev,
		HasNext:   hasNext,
		EmptyText: emptyText,
		Entries:   paged,
		Badges:    badges,
	}
}

func (s *Server) timelineEvents() []audit.TimelineEvent {
	reader, ok := s.audit.(AuditReader)
	if !ok || reader == nil {
		return nil
	}
	entries := reader.Entries()
	events := make([]audit.TimelineEvent, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		events = append(events, audit.TimelineEvent{
			Timestamp:      valueOrUnknown(entry.Timestamp),
			Scope:          timelineScope(entry),
			EventType:      valueOrUnknown(entry.Action),
			Severity:       timelineSeverity(entry),
			CorrelationID:  auditDisplayValue(entry.Correlation),
			EvidenceID:     auditDisplayValue(entry.EventID),
			ReplaySequence: "unavailable",
			ActorSource:    auditDisplayValue(timelineActorSource(entry)),
			Action:         valueOrUnknown(entry.Action),
			Target:         auditDisplayValue(entry.Target),
			Result:         auditDisplayValue(entry.Result),
			Summary:        timelineSummary(entry),
		})
	}
	return events
}

func filterTimelineEvents(events []audit.TimelineEvent, query, action string) []audit.TimelineEvent {
	query = strings.ToLower(strings.TrimSpace(query))
	action = strings.ToLower(strings.TrimSpace(action))
	if query == "" && action == "" {
		return events
	}
	filtered := make([]audit.TimelineEvent, 0, len(events))
	for _, event := range events {
		if action != "" && !strings.Contains(strings.ToLower(event.EventType), action) && !strings.Contains(strings.ToLower(event.Action), action) {
			continue
		}
		if query != "" && !timelineMatchesQuery(event, query) {
			continue
		}
		filtered = append(filtered, event)
	}
	return filtered
}

func paginateTimelineEvents(events []audit.TimelineEvent, page, pageSize int) ([]audit.TimelineEvent, bool, bool) {
	if pageSize <= 0 {
		pageSize = 20
	}
	if page <= 0 {
		page = 1
	}
	if len(events) == 0 {
		return nil, false, false
	}
	start := (page - 1) * pageSize
	if start >= len(events) {
		return nil, page > 1, false
	}
	end := start + pageSize
	if end > len(events) {
		end = len(events)
	}
	return events[start:end], start > 0, end < len(events)
}

func timelineMatchesQuery(event audit.TimelineEvent, query string) bool {
	fields := []string{
		event.Timestamp,
		event.Scope,
		event.EventType,
		event.Severity,
		event.CorrelationID,
		event.EvidenceID,
		event.ReplaySequence,
		event.ActorSource,
		event.Action,
		event.Target,
		event.Result,
		event.Summary,
	}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}
	return false
}

func timelineScope(entry audit.AuditEntry) string {
	switch {
	case strings.TrimSpace(entry.Source) != "":
		return entry.Source
	case strings.TrimSpace(entry.ActorSession) != "":
		return entry.ActorSession
	default:
		return "ui"
	}
}

func timelineActorSource(entry audit.AuditEntry) string {
	if strings.TrimSpace(entry.ActorSession) != "" {
		return entry.ActorSession
	}
	if strings.TrimSpace(entry.Source) != "" {
		return entry.Source
	}
	if strings.TrimSpace(entry.RemoteIP) != "" {
		return entry.RemoteIP
	}
	return "unknown"
}

func timelineSummary(entry audit.AuditEntry) string {
	parts := []string{valueOrUnknown(entry.Action)}
	if strings.TrimSpace(entry.Target) != "" {
		parts = append(parts, valueOrUnknown(entry.Target))
	}
	if strings.TrimSpace(entry.Result) != "" {
		parts = append(parts, valueOrUnknown(entry.Result))
	}
	return strings.Join(parts, " · ")
}

func timelineSeverity(entry audit.AuditEntry) string {
	action := strings.ToLower(strings.TrimSpace(entry.Action))
	result := strings.ToLower(strings.TrimSpace(entry.Result))
	switch {
	case strings.Contains(action, "exhausted"), strings.Contains(action, "failed"), strings.Contains(action, "error"), strings.Contains(result, "deny"), strings.Contains(result, "blocked"), strings.Contains(result, "invalid"):
		return "error"
	case strings.Contains(action, "throttled"), strings.Contains(action, "warning"), strings.Contains(result, "warning"):
		return "warning"
	case strings.Contains(action, "dry_run"), strings.Contains(action, "preview"), strings.Contains(result, "dry-run"):
		return "dryrun"
	case strings.Contains(action, "view"), strings.Contains(action, "lookup"), strings.Contains(action, "export"), strings.Contains(action, "success"), strings.Contains(result, "read-only"):
		return "healthy"
	case strings.Contains(action, "recovered"):
		return "live"
	default:
		return "badge"
	}
}

func TimelinePage(view TimelineView, csrfToken string) templ.Component {
	return ConsoleLayout(shellView{
		Title:       "Timeline",
		Headline:    "Security Timeline",
		Subtitle:    "Unified read-only chronology over audit and operator events with filtering and export.",
		Active:      "/timeline",
		BadgeLabels: view.Badges,
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if _, err := fmt.Fprint(w, `<div class="panel"><p class="muted">This page is read-only. Filters update the projection only; JSON and CSV exports are derived from the same server-side event stream.</p></div>`); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `<div class="panel"><form method="get" action="/timeline" class="stack"><div class="row" style="grid-template-columns: minmax(8rem, 9rem) minmax(0, 1fr)"><span>Search</span><span><input name="q" type="search" value="`); err != nil {
				return err
			}
			if _, err := io.WriteString(w, html.EscapeString(view.Query)); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `" placeholder="action, target, correlation id, result"/></span></div><div class="row" style="grid-template-columns: minmax(8rem, 9rem) minmax(0, 1fr)"><span>Action</span><span><input name="action" type="text" value="`); err != nil {
				return err
			}
			if _, err := io.WriteString(w, html.EscapeString(view.Action)); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `" placeholder="security_intelligence_lookup"/></span></div><div class="row" style="grid-template-columns: minmax(8rem, 9rem) minmax(0, 1fr)"><span>Limit</span><span><input name="limit" type="number" min="5" max="100" value="`); err != nil {
				return err
			}
			if _, err := io.WriteString(w, strconv.Itoa(view.PageSize)); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `" /></span></div><div class="stack" style="flex-direction:row; flex-wrap:wrap"><button type="submit">Apply filters</button><a class="badge live" href="`); err != nil {
				return err
			}
			if _, err := io.WriteString(w, html.EscapeString(timelineExportURL(view, "json"))); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `">Export JSON</a><a class="badge live" href="`); err != nil {
				return err
			}
			if _, err := io.WriteString(w, html.EscapeString(timelineExportURL(view, "csv"))); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `">Export CSV</a></div></form></div>`); err != nil {
				return err
			}
			if len(view.Entries) == 0 {
				return writeEmptyState(w, view.EmptyText)
			}
			if _, err := fmt.Fprint(w, `<table><thead><tr><th>timestamp</th><th>scope</th><th>event type</th><th>severity</th><th>correlation id</th><th>evidence id</th><th>replay seq</th><th>actor/source</th><th>action</th><th>target</th><th>result</th><th>ai</th></tr></thead><tbody>`); err != nil {
				return err
			}
			for _, entry := range view.Entries {
				if _, err := fmt.Fprintf(w, `<tr><td>%s</td><td>%s</td><td>%s</td><td><span class="badge %s">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><strong>%s</strong></td><td>%s</td><td>%s</td><td>%s</td></tr>`,
					html.EscapeString(valueOrUnknown(entry.Timestamp)),
					html.EscapeString(valueOrUnknown(entry.Scope)),
					html.EscapeString(valueOrUnknown(entry.EventType)),
					html.EscapeString(statusClass(entry.Severity)),
					html.EscapeString(strings.ToUpper(valueOrUnknown(entry.Severity))),
					html.EscapeString(auditDisplayValue(entry.CorrelationID)),
					html.EscapeString(auditDisplayValue(entry.EvidenceID)),
					html.EscapeString(auditDisplayValue(entry.ReplaySequence)),
					html.EscapeString(auditDisplayValue(entry.ActorSource)),
					html.EscapeString(valueOrUnknown(entry.Action)),
					html.EscapeString(auditDisplayValue(entry.Target)),
					html.EscapeString(auditDisplayValue(entry.Result)),
					timelineAIButtonHTML("timeline_event", timelineExplainSubjectID(entry), csrfToken),
				); err != nil {
					return err
				}
			}
			_, err := fmt.Fprint(w, `</tbody></table>`)
			return err
		}),
	})
}

func timelineExplainSubjectID(entry audit.TimelineEvent) string {
	switch {
	case strings.TrimSpace(entry.EvidenceID) != "":
		return entry.EvidenceID
	case strings.TrimSpace(entry.CorrelationID) != "":
		return entry.CorrelationID
	default:
		return strings.Join([]string{entry.Scope, entry.EventType, entry.Timestamp}, "|")
	}
}

func timelineAIButtonHTML(subjectType, subjectID, csrfToken string) string {
	return fmt.Sprintf(`<form action="/ui/ai/explain" method="post" data-ai-explain-form style="display:inline"><input type="hidden" name="subject_type" value="%s"/><input type="hidden" name="subject_id" value="%s"/><input type="hidden" name="provider_preference" value="auto"/><input type="hidden" name="csrf_token" value="%s"/><button type="submit" class="badge live">Explain with AI</button></form><div class="empty" data-ai-explain-result>AI explanation not requested yet.</div>`, html.EscapeString(subjectType), html.EscapeString(subjectID), html.EscapeString(csrfToken))
}

func timelineExportURL(view TimelineView, format string) string {
	params := url.Values{}
	if strings.TrimSpace(view.Query) != "" {
		params.Set("q", view.Query)
	}
	if strings.TrimSpace(view.Action) != "" {
		params.Set("action", view.Action)
	}
	params.Set("limit", strconv.Itoa(maxInt(1, view.PageSize)))
	params.Set("page", strconv.Itoa(maxInt(1, view.Page)))
	params.Set("format", format)
	return "/timeline?" + params.Encode()
}

func renderTimelineJSON(w http.ResponseWriter, view TimelineView) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{
		"query":   view.Query,
		"action":  view.Action,
		"page":    view.Page,
		"limit":   view.PageSize,
		"total":   view.Total,
		"entries": view.Entries,
	})
}

func renderTimelineCSV(w http.ResponseWriter, view TimelineView) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"timestamp", "scope", "event_type", "severity", "correlation_id", "evidence_id", "replay_sequence", "actor_source", "action", "target", "result", "summary"})
	for _, entry := range view.Entries {
		_ = cw.Write([]string{
			valueOrUnknown(entry.Timestamp),
			valueOrUnknown(entry.Scope),
			valueOrUnknown(entry.EventType),
			valueOrUnknown(entry.Severity),
			valueOrUnknown(entry.CorrelationID),
			valueOrUnknown(entry.EvidenceID),
			valueOrUnknown(entry.ReplaySequence),
			valueOrUnknown(entry.ActorSource),
			valueOrUnknown(entry.Action),
			valueOrUnknown(entry.Target),
			valueOrUnknown(entry.Result),
			valueOrUnknown(entry.Summary),
		})
	}
	cw.Flush()
}

func parsePositiveInt(value string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func clampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
