package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/detect"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

var pipelineSources = []struct{ slug, display string }{
	{"cloudflare_waf", "Cloudflare WAF"},
	{"crowdsec_waf", "CrowdSec WAF"},
	{"openresty_waf", "OpenResty WAF"},
}

func (s *Server) handlePipelineHealthPage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()
	view := s.buildPipelineHealthView(ctx)
	_ = PipelineHealthPage(view).Render(ctx, w)
}

func (s *Server) buildPipelineHealthView(ctx context.Context) PipelineHealthView {
	ctx, cancel := stableUIReadContext(ctx)
	defer cancel()
	if s.evidence == nil {
		return PipelineHealthView{Error: "Evidence store not available — daemon not yet started."}
	}

	detectors := make(map[string]detect.Result)
	for _, det := range detect.RunAll(s.buildDetectConfig()) {
		detectors[det.Name] = det
	}

	rows := make([]PipelineHealthRow, 0, len(pipelineSources))
	total := PipelineHealthRow{Source: "Total"}
	var totalLatest time.Time
	for _, src := range pipelineSources {
		row := PipelineHealthRow{Source: src.display}
		row.Classified, _ = s.evidence.Count(ctx, reporting.EvidenceSearchOptions{Source: src.slug})
		row.Reported, _ = s.evidence.Count(ctx, reporting.EvidenceSearchOptions{Source: src.slug, AbuseIPDBReported: true})
		row.Suppressed, _ = s.evidence.Count(ctx, reporting.EvidenceSearchOptions{Source: src.slug, Suppressed: true})
		row.Pending, _ = s.evidence.Count(ctx, reporting.EvidenceSearchOptions{Source: src.slug, Decision: "report_pending"})
		if latest, ok := s.latestEvidenceForSource(ctx, src.slug); ok {
			row.LastEventAt = formatEventTimestamp(latest.Timestamp)
			row.LatestEvidenceID = latest.EvidenceID
			if latest.Timestamp.After(totalLatest) {
				totalLatest = latest.Timestamp
				total.LastEventAt = row.LastEventAt
				total.LatestEvidenceID = row.LatestEvidenceID
			}
		}
		if det, ok := detectors[detectorNameForSourceSlug(src.slug)]; ok {
			row.State = pipelineSourceState(det, row.Classified)
		} else {
			row.State = "unavailable"
		}
		if row.State == "" {
			row.State = "unavailable"
		}
		rows = append(rows, row)
		total.Classified += row.Classified
		total.Reported += row.Reported
		total.Suppressed += row.Suppressed
		total.Pending += row.Pending
	}
	if total.State == "" {
		if total.Classified > 0 {
			total.State = "active"
		} else {
			total.State = "no events yet"
		}
	}

	return PipelineHealthView{
		Rows:  rows,
		Total: total,
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
			if _, err := fmt.Fprint(w, `<div class="panel"><div class="table-wrap"><table><thead><tr><th>Source</th><th>State</th><th>Classified</th><th>Reported</th><th>Suppressed</th><th>Pending</th><th>Last event</th><th>Latest evidence</th></tr></thead><tbody>`); err != nil {
				return err
			}
			for _, row := range view.Rows {
				lastEvent := "no events yet"
				if row.LastEventAt != "" {
					lastEvent = row.LastEventAt
				}
				lastEventCell := fmt.Sprintf(`<span class="cell-clip" title="%s">%s</span>`, html.EscapeString(lastEvent), html.EscapeString(lastEvent))
				latestEvidence := `<span class="muted">none</span>`
				if row.LatestEvidenceID != "" {
					latestEvidence = evidenceDetailLinkHTML(row.LatestEvidenceID)
				}
				if _, err := fmt.Fprintf(w,
					`<tr><td>%s</td><td><span class="badge %s">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
					html.EscapeString(row.Source),
					pipelineStateBadgeClass(row.State),
					html.EscapeString(row.State),
					strconv.Itoa(row.Classified),
					strconv.Itoa(row.Reported),
					strconv.Itoa(row.Suppressed),
					strconv.Itoa(row.Pending),
					lastEventCell,
					latestEvidence,
				); err != nil {
					return err
				}
			}
			t := view.Total
			if _, err := fmt.Fprintf(w,
				`</tbody><tfoot><tr><th>%s</th><th><span class="badge %s">%s</span></th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></tfoot></table></div></div>`,
				html.EscapeString(t.Source),
				pipelineStateBadgeClass(t.State),
				html.EscapeString(t.State),
				strconv.Itoa(t.Classified),
				strconv.Itoa(t.Reported),
				strconv.Itoa(t.Suppressed),
				strconv.Itoa(t.Pending),
				html.EscapeString(t.LastEventAt),
				evidenceDetailLinkHTML(t.LatestEvidenceID),
			); err != nil {
				return err
			}
			return nil
		}),
	})
}

func detectorNameForSourceSlug(slug string) string {
	switch slug {
	case "cloudflare_waf":
		return "cloudflare"
	case "crowdsec_waf":
		return "crowdsec"
	case "openresty_waf":
		return "openresty"
	default:
		return ""
	}
}
