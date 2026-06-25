package ui

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/runtime/timeline"
	"github.com/jm/security-automation-go/internal/security/audit"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

// timelineRuntimeScopeID is the scope ID the daemon's state machine publishes
// lifecycle-transition events under (see engine.StateMachine.Transition,
// cmd/cf-sync/runtime.go) when no per-run RuntimeContext scope override is
// present — the case for nearly all transitions in this single-tenant
// deployment model.
const timelineRuntimeScopeID = "default"

type TimelineView struct {
	Query      string
	Action     string
	Source     string // filter: "audit", "waf", or "" (all)
	Page       int
	PageSize   int
	Total      int
	HasPrev    bool
	HasNext    bool
	EmptyText  string
	Entries    []audit.TimelineEvent
	Badges     []StatusItem
	RefreshURL string
}

// timedEvent pairs a parsed wall-clock time with its event for a stable merged sort.
type timedEvent struct {
	t     time.Time
	event audit.TimelineEvent
}

func (s *Server) timelineView(r *http.Request) TimelineView {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	page := parsePositiveInt(r.URL.Query().Get("page"), 1)
	pageSize := clampInt(parsePositiveInt(r.URL.Query().Get("limit"), 20), 5, 100)
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))

	hasFilter := query != "" || action != "" || source != ""
	events := s.timelineEvents(ctx, timelineEvidenceReadLimit(page, pageSize, hasFilter || isTimelineExport(format)))
	events = filterTimelineEvents(events, query, action, source)
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
	if source != "" {
		badges = append(badges, StatusItem{Label: "Source", Level: "warning", Detail: source})
	}

	emptyText := "No timeline events yet. Audit entries and WAF events will appear here when the daemon processes security events."
	if query != "" || action != "" || source != "" {
		emptyText = "No matching timeline events."
	}

	return TimelineView{
		Query:      query,
		Action:     action,
		Source:     source,
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		HasPrev:    hasPrev,
		HasNext:    hasNext,
		EmptyText:  emptyText,
		Entries:    paged,
		Badges:     badges,
		RefreshURL: r.URL.RequestURI(),
	}
}

const (
	// timelineCacheTTL bounds how often the audit+evidence merge is recomputed.
	// Without this, an operator repeatedly refreshing /timeline during a live
	// incident forces a re-merge, re-sort, and re-paginate on every request.
	timelineCacheTTL = 3 * time.Second

	// timelineEvidenceMaxWindow is the largest evidence read-model slice the UI
	// will merge for a single /timeline projection. It keeps large datasets
	// bounded while preserving enough history for filters and exports.
	timelineEvidenceMaxWindow = 1000
	timelineEvidenceMinWindow = 100
	timelineEvidenceLookahead = 5
	timelineEvidenceComplete  = -1
)

// allTimelineEvents merges audit entries and WAF evidence records into a single
// reverse-chronological stream, sorted by parsed wall-clock time. The merged
// result is cached for timelineCacheTTL to bound the cost of repeated
// requests against a growing history (see timelineCacheTTL).
//
// Evidence is read completely in bounded pages. Runtime daemon lifecycle events
// (startup, config reloads) are read from the scoped runtime event store.
func (s *Server) allTimelineEvents(ctx context.Context) []audit.TimelineEvent {
	return s.timelineEvents(ctx, timelineEvidenceComplete)
}

func (s *Server) timelineEvents(ctx context.Context, evidenceLimit int) []audit.TimelineEvent {
	cacheLimit := evidenceLimit
	if evidenceLimit != timelineEvidenceComplete {
		evidenceLimit = clampInt(evidenceLimit, 1, timelineEvidenceMaxWindow)
		cacheLimit = evidenceLimit
	}
	s.timelineMu.Lock()
	if !s.timelineCacheAt.IsZero() && s.timelineCacheLimit == cacheLimit && time.Since(s.timelineCacheAt) < timelineCacheTTL {
		cached := s.timelineCache
		s.timelineMu.Unlock()
		return cached
	}
	s.timelineMu.Unlock()

	events := s.computeAllTimelineEvents(ctx, evidenceLimit)

	s.timelineMu.Lock()
	s.timelineCache = events
	s.timelineCacheAt = time.Now()
	s.timelineCacheLimit = cacheLimit
	s.timelineMu.Unlock()

	return events
}

func timelineEvidenceReadLimit(page, pageSize int, hasFilter bool) int {
	if hasFilter {
		return timelineEvidenceComplete
	}
	page = maxInt(1, page)
	pageSize = clampInt(pageSize, 5, 100)
	needed := page * pageSize
	return clampInt(needed+(pageSize*timelineEvidenceLookahead), timelineEvidenceMinWindow, timelineEvidenceMaxWindow)
}

func isTimelineExport(format string) bool {
	return format == "json" || format == "csv"
}

func (s *Server) computeAllTimelineEvents(ctx context.Context, evidenceLimit int) []audit.TimelineEvent {
	ctx, cancel := stableUIReadContext(ctx)
	defer cancel()
	var timed []timedEvent

	if reader, ok := s.audit.(AuditReader); ok && reader != nil {
		for _, entry := range reader.Entries() {
			// Parse the timestamp for correct sort ordering. RFC3339Nano strings
			// cannot be compared lexicographically when fractional-second width varies.
			t, _ := time.Parse(time.RFC3339Nano, entry.Timestamp)
			timed = append(timed, timedEvent{t: t, event: auditEntryToTimelineEvent(entry)})
		}
	}

	for _, ev := range s.timelineEvidenceRows(ctx, evidenceLimit) {
		timed = append(timed, timedEvent{t: ev.Timestamp, event: evidenceToTimelineEvent(ev)})
	}

	if s.eventStore != nil {
		entries, err := timeline.NewCollector(s.eventStore).Assemble(ctx, timelineRuntimeScopeID)
		if err == nil {
			for _, entry := range entries {
				timed = append(timed, timedEvent{t: entry.Timestamp, event: runtimeEntryToTimelineEvent(entry)})
			}
		}
	}

	sort.Slice(timed, func(i, j int) bool {
		return timed[i].t.After(timed[j].t)
	})

	events := make([]audit.TimelineEvent, 0, len(timed))
	for _, te := range timed {
		events = append(events, te.event)
	}
	return events
}

func (s *Server) timelineEvidenceRows(ctx context.Context, evidenceLimit int) []reporting.DecisionEvidence {
	if s.evidence == nil {
		return nil
	}
	if evidenceLimit != timelineEvidenceComplete {
		evs, err := s.evidence.Search(ctx, reporting.EvidenceSearchOptions{Limit: evidenceLimit})
		if err == nil {
			return evs
		}
		return nil
	}

	var all []reporting.DecisionEvidence
	for offset := 0; ; offset += timelineEvidenceMaxWindow {
		evs, err := s.evidence.Search(ctx, reporting.EvidenceSearchOptions{
			Limit:  timelineEvidenceMaxWindow,
			Offset: offset,
		})
		if err != nil || len(evs) == 0 {
			return all
		}
		all = append(all, evs...)
		if len(evs) < timelineEvidenceMaxWindow {
			return all
		}
	}
}

func auditEntryToTimelineEvent(entry audit.AuditEntry) audit.TimelineEvent {
	return audit.TimelineEvent{
		Timestamp:      valueOrUnknown(entry.Timestamp),
		Scope:          timelineScope(entry),
		EventType:      valueOrUnknown(entry.Action),
		Severity:       timelineSeverity(entry),
		CorrelationID:  auditDisplayValue(entry.Correlation),
		EvidenceID:     "", // audit entries carry no evidence record; CorrelationID covers the correlation use-case
		ReplaySequence: "unavailable",
		ActorSource:    auditDisplayValue(timelineActorSource(entry)),
		Action:         valueOrUnknown(entry.Action),
		Target:         auditDisplayValue(entry.Target),
		Result:         auditDisplayValue(entry.Result),
		Summary:        timelineSummary(entry),
	}
}

func resolvedAuditEventID(entry audit.AuditEntry) string {
	if strings.TrimSpace(entry.EventID) != "" {
		return entry.EventID
	}
	return strings.TrimSpace(entry.Correlation)
}

func evidenceToTimelineEvent(ev reporting.DecisionEvidence) audit.TimelineEvent {
	eventType := "waf_classified"
	severity := "badge"
	action := ev.Decision
	result := ev.Decision

	switch {
	case ev.AbuseIPDBReported:
		eventType = "abuseipdb_reported"
		severity = "error"
		action = "abuseipdb_reported"
		result = "reported"
	case ev.Suppressed:
		eventType = "waf_suppressed"
		severity = "warning"
		action = "waf_suppressed"
		result = "suppressed"
		if ev.SuppressionReason != "" {
			result += ":" + ev.SuppressionReason
		}
	case ev.Decision == "report_pending":
		severity = "live"
	}

	summary := ev.Source
	if ev.IP != "" {
		summary += " · " + ev.IP
	}
	if ev.AbuseType != "" {
		summary += " · " + ev.AbuseType
	}

	ts := ""
	if !ev.Timestamp.IsZero() {
		ts = ev.Timestamp.UTC().Format(time.RFC3339Nano)
	}

	return audit.TimelineEvent{
		Timestamp:   ts,
		Scope:       ev.Source,
		EventType:   eventType,
		Severity:    severity,
		EvidenceID:  ev.EvidenceID,
		ActorSource: ev.Source,
		Action:      action,
		Target:      ev.IP,
		Result:      result,
		Summary:     summary,
	}
}

// runtimeEntryToTimelineEvent projects a runtime event-journal entry (real
// daemon lifecycle transitions, with real sequence numbers — see
// internal/runtime/timeline.Collector) into the unified timeline stream.
// Unlike audit/evidence rows, ReplaySequence here is never a placeholder:
// it is the entry's actual journal sequence number.
func runtimeEntryToTimelineEvent(entry timeline.TimelineEntry) audit.TimelineEvent {
	summary := entry.Type
	if reason, ok := entry.Metadata["reason"].(string); ok && reason != "" {
		summary = entry.Type + " · " + reason
	}
	return audit.TimelineEvent{
		Timestamp:      entry.Timestamp.UTC().Format(time.RFC3339Nano),
		Scope:          "runtime",
		EventType:      "runtime_" + entry.Type,
		Severity:       runtimeEventSeverity(entry.Category),
		CorrelationID:  entry.CorrelationID,
		ReplaySequence: strconv.FormatUint(entry.Sequence, 10),
		ActorSource:    valueOrUnknown(entry.Actor),
		Action:         entry.Type,
		Summary:        summary,
	}
}

func runtimeEventSeverity(category events.Category) string {
	switch category {
	case events.CategoryRollback:
		return "error"
	case events.CategoryDrift, events.CategoryFencing:
		return "warning"
	case events.CategoryLifecycle:
		return "live"
	default:
		return "badge"
	}
}

// wafScopes is the set of evidence source values that identify WAF pipeline events.
var wafScopes = map[string]bool{
	"cloudflare_waf": true,
	"crowdsec_waf":   true,
	"openresty_waf":  true,
}

func isWAFScope(scope string) bool { return wafScopes[scope] }

func filterTimelineEvents(events []audit.TimelineEvent, query, action, source string) []audit.TimelineEvent {
	query = strings.ToLower(strings.TrimSpace(query))
	action = strings.ToLower(strings.TrimSpace(action))
	source = strings.ToLower(strings.TrimSpace(source))
	if query == "" && action == "" && source == "" {
		return events
	}
	filtered := make([]audit.TimelineEvent, 0, len(events))
	for _, event := range events {
		switch source {
		case "waf":
			if !isWAFScope(event.Scope) {
				continue
			}
		case "audit":
			if isWAFScope(event.Scope) || event.Scope == "runtime" {
				continue
			}
		case "runtime":
			if event.Scope != "runtime" {
				continue
			}
		}
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
		Subtitle:    "Unified read-only chronology over audit and WAF events with filtering and export.",
		Active:      "/timeline",
		BadgeLabels: view.Badges,
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if _, err := fmt.Fprintf(w, `<div class="stack" data-live-shell="timeline" data-live-refresh-url="%s" data-live-refresh-interval="10000"><div class="panel collapsible-panel" data-collapsible-panel="true" data-collapsible-key="timeline-read-model" data-collapsed="false"><div class="collapsible-head"><div><h2>Read model</h2><p class="muted">Server-rendered projection over audit, evidence, and runtime lineage.</p></div><button type="button" class="badge" data-collapsible-toggle="true" aria-expanded="true">Collapse</button></div><div class="collapsible-body"><p class="muted">This page is read-only. Filters update the projection only; JSON and CSV exports are derived from the same server-side event stream.</p><p class="muted"><a href="/timeline/correlated" class="badge">Correlated view</a> — events grouped by IP across all sources.</p></div></div>`, html.EscapeString(view.RefreshURL)); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `<div class="panel collapsible-panel" data-collapsible-panel="true" data-collapsible-key="timeline-filters" data-collapsed="false"><div class="collapsible-head"><div><h2>Filters</h2><p class="muted">Server-side filtering; no browser-side business logic.</p></div><button type="button" class="badge" data-collapsible-toggle="true" aria-expanded="true">Collapse</button></div><div class="collapsible-body"><form method="get" action="/timeline" class="stack" data-live-search-form="true">`); err != nil {
				return err
			}
			// Source filter row
			if _, err := fmt.Fprint(w, `<div class="row" style="grid-template-columns: minmax(8rem, 9rem) minmax(0, 1fr)"><span>Source</span><span><select name="source"><option value=""`); err != nil {
				return err
			}
			if view.Source == "" {
				if _, err := fmt.Fprint(w, ` selected`); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `>All events</option><option value="waf"`); err != nil {
				return err
			}
			if view.Source == "waf" {
				if _, err := fmt.Fprint(w, ` selected`); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `>WAF Events</option><option value="audit"`); err != nil {
				return err
			}
			if view.Source == "audit" {
				if _, err := fmt.Fprint(w, ` selected`); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `>Audit Trail</option><option value="runtime"`); err != nil {
				return err
			}
			if view.Source == "runtime" {
				if _, err := fmt.Fprint(w, ` selected`); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `>Runtime Lineage</option></select></span></div>`); err != nil {
				return err
			}
			// Search row
			if _, err := fmt.Fprint(w, `<div class="row" style="grid-template-columns: minmax(8rem, 9rem) minmax(0, 1fr)"><span>Search</span><span><input name="q" type="search" value="`); err != nil {
				return err
			}
			if _, err := io.WriteString(w, html.EscapeString(view.Query)); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `" placeholder="action, target, correlation id, result"/></span></div>`); err != nil {
				return err
			}
			// Action row
			if _, err := fmt.Fprint(w, `<div class="row" style="grid-template-columns: minmax(8rem, 9rem) minmax(0, 1fr)"><span>Action</span><span><input name="action" type="text" value="`); err != nil {
				return err
			}
			if _, err := io.WriteString(w, html.EscapeString(view.Action)); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `" placeholder="security_intelligence_lookup"/></span></div>`); err != nil {
				return err
			}
			// Limit row
			if _, err := fmt.Fprint(w, `<div class="row" style="grid-template-columns: minmax(8rem, 9rem) minmax(0, 1fr)"><span>Limit</span><span><input name="limit" type="number" min="5" max="100" value="`); err != nil {
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
			if _, err := fmt.Fprint(w, `">Export CSV</a></div></form></div></div>`); err != nil {
				return err
			}

			if len(view.Entries) == 0 {
				if err := writeEmptyState(w, view.EmptyText); err != nil {
					return err
				}
				_, err := fmt.Fprint(w, `</div>`)
				return err
			}
			if _, err := fmt.Fprint(w, `<div class="table-wrap"><table><colgroup><col style="width:10rem"><col style="width:6rem"><col style="width:9rem"><col style="width:5rem"><col style="width:10rem"><col style="width:10rem"><col style="width:7rem"><col style="width:9rem"><col style="width:9rem"><col style="width:9rem"><col style="width:9rem"><col></colgroup><thead><tr><th>timestamp</th><th>scope</th><th>event type</th><th>severity</th><th>correlation id</th><th>evidence id</th><th>replay seq</th><th>actor/source</th><th>action</th><th>target</th><th>result</th><th>ai</th></tr></thead><tbody>`); err != nil {
				return err
			}
			for _, entry := range view.Entries {
				if _, err := fmt.Fprintf(w, `<tr><td>%s</td><td>%s</td><td>%s</td><td><span class="badge %s">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><strong>%s</strong></td><td>%s</td><td>%s</td><td>%s</td></tr>`,
					html.EscapeString(valueOrUnknown(entry.Timestamp)),
					html.EscapeString(valueOrUnknown(entry.Scope)),
					html.EscapeString(valueOrUnknown(entry.EventType)),
					html.EscapeString(statusClass(entry.Severity)),
					html.EscapeString(strings.ToUpper(valueOrUnknown(entry.Severity))),
					compactCopyHTML(auditDisplayValue(entry.CorrelationID), 14, "Correlation copied"),
					evidenceDetailLinkHTML(entry.EvidenceID),
					compactCopyHTML(auditDisplayValue(entry.ReplaySequence), 10, "Replay sequence copied"),
					compactCopyHTML(auditDisplayValue(entry.ActorSource), 14, "Actor copied"),
					html.EscapeString(valueOrUnknown(entry.Action)),
					timelineTargetCell(entry.Target),
					compactCopyHTML(auditDisplayValue(entry.Result), 16, "Result copied"),
					timelineAIButtonHTML("timeline_event", timelineExplainSubjectID(entry), csrfToken),
				); err != nil {
					return err
				}
			}
			_, err := fmt.Fprint(w, `</tbody></table></div></div>`)
			return err
		}),
	})
}

// timelineTargetCell returns HTML for the target column: an IP becomes a link
// to /forensic?ip=X; other values are rendered as plain escaped text.
func timelineTargetCell(target string) string {
	v := auditDisplayValue(target)
	if addr, err := netip.ParseAddr(strings.TrimSpace(target)); err == nil && addr.IsValid() {
		watchBtn := fmt.Sprintf(` <button type="button" class="badge" data-watchlist-add="true" data-watchlist-type="ip" data-watchlist-value="%s" data-watchlist-label="%s" title="Add to watchlist" style="min-height:auto;padding:.1rem .3rem;font-size:.8rem;box-shadow:none">☆</button>`,
			html.EscapeString(addr.String()),
			html.EscapeString(addr.String()),
		)
		incidentLink := fmt.Sprintf(` <a href="/incident?ip=%s" class="badge" title="Focus Incident">⊕</a>`, url.QueryEscape(addr.String()))
		return compactLinkCopyHTML("/forensic?ip="+url.QueryEscape(addr.String()), addr.String(), "Explain this IP", "Forensic Lookup", "IP copied", 14) + watchBtn + incidentLink
	}
	return compactCopyHTML(v, 18, "Target copied")
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
	if strings.TrimSpace(view.Source) != "" {
		params.Set("source", view.Source)
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
		"source":  view.Source,
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
