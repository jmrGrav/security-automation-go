package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"strconv"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

var pipelineSources = []struct{ slug, display string }{
	{"cloudflare_waf", "Cloudflare WAF"},
	{"crowdsec_waf", "CrowdSec WAF"},
	{"openresty_waf", "OpenResty WAF"},
}

func (s *Server) handlePipelineHealthPage(w http.ResponseWriter, r *http.Request) {
	view := s.buildPipelineHealthView(r.Context())
	_ = PipelineHealthPage(view).Render(r.Context(), w)
}

func (s *Server) buildPipelineHealthView(ctx context.Context) PipelineHealthView {
	if s.evidence == nil {
		return PipelineHealthView{Error: "Evidence store not available — daemon not yet started."}
	}

	// Load up to 100k rows for counting. Counts become unreliable past this cap.
	const searchCap = 100_000
	all, err := s.evidence.Search(ctx, reporting.EvidenceSearchOptions{Limit: searchCap})
	if err != nil {
		return PipelineHealthView{Error: fmt.Sprintf("Error loading evidence: %v", err)}
	}

	counters := make(map[string]*PipelineHealthRow, len(pipelineSources))
	for _, src := range pipelineSources {
		counters[src.slug] = &PipelineHealthRow{Source: src.display}
	}

	for _, ev := range all {
		row, ok := counters[ev.Source]
		if !ok {
			continue
		}
		row.Classified++
		switch {
		case ev.AbuseIPDBReported:
			row.Reported++
		case ev.Suppressed:
			row.Suppressed++
		case ev.Decision == "report_pending":
			row.Pending++
		}
	}

	rows := make([]PipelineHealthRow, 0, len(pipelineSources))
	total := PipelineHealthRow{Source: "Total"}
	for _, src := range pipelineSources {
		row := *counters[src.slug]
		rows = append(rows, row)
		total.Classified += row.Classified
		total.Reported += row.Reported
		total.Suppressed += row.Suppressed
		total.Pending += row.Pending
	}

	return PipelineHealthView{
		Rows:      rows,
		Total:     total,
		Truncated: len(all) >= searchCap,
	}
}

func PipelineHealthPage(view PipelineHealthView) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Pipeline Health",
		Headline: "Pipeline Health Matrix",
		Subtitle: "Per-source breakdown of classified, reported, suppressed, and pending WAF events.",
		Active:   "/pipeline",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if view.Error != "" {
				return writeEmptyState(w, view.Error)
			}
			if view.Truncated {
				if _, err := fmt.Fprint(w, `<div class="panel"><p class="warning">Result set hit the 100 000-row cap — counts may be incomplete.</p></div>`); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `<div class="panel"><table><thead><tr><th>Source</th><th>Classified</th><th>Reported</th><th>Suppressed</th><th>Pending</th></tr></thead><tbody>`); err != nil {
				return err
			}
			for _, row := range view.Rows {
				if _, err := fmt.Fprintf(w,
					`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
					html.EscapeString(row.Source),
					strconv.Itoa(row.Classified),
					strconv.Itoa(row.Reported),
					strconv.Itoa(row.Suppressed),
					strconv.Itoa(row.Pending),
				); err != nil {
					return err
				}
			}
			t := view.Total
			if _, err := fmt.Fprintf(w,
				`</tbody><tfoot><tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></tfoot></table></div>`,
				html.EscapeString(t.Source),
				strconv.Itoa(t.Classified),
				strconv.Itoa(t.Reported),
				strconv.Itoa(t.Suppressed),
				strconv.Itoa(t.Pending),
			); err != nil {
				return err
			}
			return nil
		}),
	})
}
