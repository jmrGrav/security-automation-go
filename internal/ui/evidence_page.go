package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

const evidencePageSize = 50

type EvidenceView struct {
	Filter    string
	Page      int
	PageSize  int
	Total     int
	HasPrev   bool
	HasNext   bool
	Entries   []reporting.DecisionEvidence
	Badges    []StatusItem
	EmptyText string
}

func (s *Server) handleEvidencePage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()
	filter := strings.TrimSpace(r.URL.Query().Get("filter"))
	page := parsePositiveInt(r.URL.Query().Get("page"), 1)
	pageSize := clampInt(parsePositiveInt(r.URL.Query().Get("limit"), evidencePageSize), 10, 200)

	view := EvidenceView{
		Filter:    filter,
		Page:      page,
		PageSize:  pageSize,
		EmptyText: "No WAF events recorded yet. Events will appear here once the daemon processes security events.",
	}

	if s.evidence == nil {
		view.EmptyText = "Evidence store not available — daemon not yet started."
		_ = EvidencePage(view).Render(ctx, w)
		return
	}

	baseOpts := reporting.EvidenceSearchOptions{}
	switch filter {
	case "reported":
		baseOpts.AbuseIPDBReported = true
	case "suppressed":
		baseOpts.Suppressed = true
	}

	total, err := s.evidence.Count(ctx, baseOpts)
	if err != nil {
		view.EmptyText = fmt.Sprintf("Error loading evidence: %v", err)
		_ = EvidencePage(view).Render(ctx, w)
		return
	}

	offset := (page - 1) * pageSize
	pageOpts := baseOpts
	pageOpts.Limit = pageSize
	pageOpts.Offset = offset
	entries, err := s.evidence.Search(ctx, pageOpts)
	if err != nil {
		view.EmptyText = fmt.Sprintf("Error loading evidence: %v", err)
		_ = EvidencePage(view).Render(ctx, w)
		return
	}

	hasPrev := offset > 0
	hasNext := offset+pageSize < total

	reportedCount, _ := s.evidence.Count(ctx, reporting.EvidenceSearchOptions{AbuseIPDBReported: true})

	badges := []StatusItem{
		{Label: "Total events", Level: "healthy", Detail: strconv.Itoa(total)},
		{Label: "Reported", Level: "live", Detail: strconv.Itoa(reportedCount)},
		{Label: "Page", Level: "badge", Detail: fmt.Sprintf("%d / %d", page, maxInt(1, (total+pageSize-1)/pageSize))},
	}
	if filter != "" {
		badges = append(badges, StatusItem{Label: "Filter", Level: "warning", Detail: filter})
	}

	view.Total = total
	view.HasPrev = hasPrev
	view.HasNext = hasNext
	view.Entries = entries
	view.Badges = badges
	if total == 0 {
		view.EmptyText = "No matching events."
	}

	_ = EvidencePage(view).Render(ctx, w)
}

func EvidencePage(view EvidenceView) templ.Component {
	return ConsoleLayout(shellView{
		Title:       "WAF Events",
		Headline:    "WAF Event History",
		Subtitle:    "Paginated view of all processed WAF events from the scoped evidence store.",
		Active:      "/evidence",
		BadgeLabels: view.Badges,
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if _, err := fmt.Fprint(w, `<div class="panel"><form method="get" action="/evidence" class="stack"><div class="row" style="grid-template-columns: minmax(8rem, 9rem) minmax(0, 1fr)"><span>Filter</span><span><select name="filter"><option value=""`); err != nil {
				return err
			}
			if view.Filter == "" {
				if _, err := fmt.Fprint(w, ` selected`); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `>All events</option><option value="reported"`); err != nil {
				return err
			}
			if view.Filter == "reported" {
				if _, err := fmt.Fprint(w, ` selected`); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `>Reported to AbuseIPDB</option><option value="suppressed"`); err != nil {
				return err
			}
			if view.Filter == "suppressed" {
				if _, err := fmt.Fprint(w, ` selected`); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `>Low confidence (suppressed)</option></select></span></div><div class="row" style="grid-template-columns: minmax(8rem, 9rem) minmax(0, 1fr)"><span>Limit</span><span><input name="limit" type="number" min="10" max="200" value="`); err != nil {
				return err
			}
			if _, err := io.WriteString(w, strconv.Itoa(view.PageSize)); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `" /></span></div><div class="stack" style="flex-direction:row; flex-wrap:wrap"><button type="submit">Apply</button>`); err != nil {
				return err
			}
			if view.HasPrev {
				prevURL := fmt.Sprintf(`/evidence?filter=%s&page=%d&limit=%d`, html.EscapeString(view.Filter), view.Page-1, view.PageSize)
				if _, err := fmt.Fprintf(w, `<a class="badge" href="%s">← Prev</a>`, prevURL); err != nil {
					return err
				}
			}
			if view.HasNext {
				nextURL := fmt.Sprintf(`/evidence?filter=%s&page=%d&limit=%d`, html.EscapeString(view.Filter), view.Page+1, view.PageSize)
				if _, err := fmt.Fprintf(w, `<a class="badge" href="%s">Next →</a>`, nextURL); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `</div></form></div>`); err != nil {
				return err
			}

			if len(view.Entries) == 0 {
				return writeEmptyState(w, view.EmptyText)
			}

			if _, err := fmt.Fprint(w, `<div class="table-wrap"><table><colgroup><col style="width:10rem"><col style="width:12rem"><col style="width:8rem"><col style="width:9rem"><col style="width:8rem"><col style="width:4rem"><col style="width:5rem"><col style="width:8rem"><col><col style="width:7rem"></colgroup><thead><tr><th>timestamp</th><th>evidence id</th><th>source</th><th>IP</th><th>type</th><th>score</th><th>confidence</th><th>decision</th><th>suppression</th><th>status</th></tr></thead><tbody>`); err != nil {
				return err
			}
			for _, ev := range view.Entries {
				statusBadge := `<span class="badge">ok</span>`
				suppression := `<span class="muted">none</span>`
				switch {
				case ev.AbuseIPDBReported:
					statusBadge = `<span class="badge bad" title="reported to AbuseIPDB">AbuseIPDB</span>`
				case ev.Suppressed:
					statusBadge = `<span class="badge warning" title="suppressed">suppressed</span>`
					if ev.SuppressionReason != "" {
						reason := html.EscapeString(ev.SuppressionReason)
						suppression = `<span class="badge warning cell-clip" title="` + reason + `">` + reason + `</span>`
					}
				case ev.Decision == "report_pending":
					statusBadge = `<span class="badge live" title="report pending">pending</span>`
				}
				evidenceLink := evidenceDetailLinkHTML(ev.EvidenceID)
				ipCell := fmt.Sprintf(`<a href="/forensic?ip=%s" title="Explain this IP" data-live-panel-link="true" data-live-panel-title="Forensic Lookup">%s</a>`,
					html.EscapeString(ev.IP), html.EscapeString(ev.IP))
				if _, err := fmt.Fprintf(w, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%.2f</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
					html.EscapeString(ev.Timestamp.Format("2006-01-02 15:04:05")),
					evidenceLink,
					html.EscapeString(ev.Source),
					ipCell,
					html.EscapeString(ev.AbuseType),
					ev.RiskScore,
					ev.Confidence,
					html.EscapeString(ev.Decision),
					suppression,
					statusBadge,
				); err != nil {
					return err
				}
			}
			_, err := fmt.Fprint(w, `</tbody></table></div>`)
			return err
		}),
	})
}
