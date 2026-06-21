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
	{"nginx_http_error", "HTTP Errors (4xx/5xx)"},
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
		row.SuppressionBreakdown = s.buildSuppressionBreakdown(ctx, src.slug)
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
		total.SuppressionBreakdown.ProtectedTarget += row.SuppressionBreakdown.ProtectedTarget
		total.SuppressionBreakdown.BenignSignal += row.SuppressionBreakdown.BenignSignal
		total.SuppressionBreakdown.LowConfidence += row.SuppressionBreakdown.LowConfidence
		total.SuppressionBreakdown.DuplicateReport += row.SuppressionBreakdown.DuplicateReport
		total.SuppressionBreakdown.RecentlyReported += row.SuppressionBreakdown.RecentlyReported
		total.SuppressionBreakdown.NoCategories += row.SuppressionBreakdown.NoCategories
		total.SuppressionBreakdown.Other += row.SuppressionBreakdown.Other
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

func (s *Server) buildSuppressionBreakdown(ctx context.Context, source string) PipelineSuppressionBreakdown {
	count := func(reason string) int {
		n, _ := s.evidence.Count(ctx, reporting.EvidenceSearchOptions{Source: source, SuppressionReason: reason})
		return n
	}
	bd := PipelineSuppressionBreakdown{
		ProtectedTarget:  count("protected_target"),
		BenignSignal:     count("benign_signal"),
		LowConfidence:    count("low_confidence"),
		DuplicateReport:  count("duplicate_report"),
		RecentlyReported: count("abuseipdb_recently_reported"),
		NoCategories:     count("no_abuse_categories"),
	}
	// Other = Suppressed total minus known reasons (covers malformed, dedup_store_error, etc.)
	return bd
}

func suppressionBreakdownTitle(bd PipelineSuppressionBreakdown) string {
	if bd.ProtectedTarget == 0 && bd.BenignSignal == 0 && bd.LowConfidence == 0 &&
		bd.DuplicateReport == 0 && bd.RecentlyReported == 0 && bd.NoCategories == 0 {
		return ""
	}
	var parts []string
	if bd.ProtectedTarget > 0 {
		parts = append(parts, fmt.Sprintf("protected_target=%d", bd.ProtectedTarget))
	}
	if bd.BenignSignal > 0 {
		parts = append(parts, fmt.Sprintf("benign_signal=%d", bd.BenignSignal))
	}
	if bd.LowConfidence > 0 {
		parts = append(parts, fmt.Sprintf("low_confidence=%d", bd.LowConfidence))
	}
	if bd.DuplicateReport > 0 {
		parts = append(parts, fmt.Sprintf("duplicate=%d", bd.DuplicateReport))
	}
	if bd.RecentlyReported > 0 {
		parts = append(parts, fmt.Sprintf("recently_reported=%d", bd.RecentlyReported))
	}
	if bd.NoCategories > 0 {
		parts = append(parts, fmt.Sprintf("no_categories=%d", bd.NoCategories))
	}
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += " "
		}
		result += p
	}
	return result
}

func buildSuppressedCell(count int, bd PipelineSuppressionBreakdown) string {
	detail := suppressionBreakdownTitle(bd)
	if detail == "" {
		return strconv.Itoa(count)
	}
	return fmt.Sprintf(`<span title="%s">%d</span><br><span class="muted" style="font-size:.75em;white-space:pre-wrap">%s</span>`,
		html.EscapeString(detail),
		count,
		html.EscapeString(detail),
	)
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
			if _, err := fmt.Fprint(w, `<div class="panel"><div class="table-wrap"><table><colgroup><col style="width:13rem"><col style="width:9rem"><col style="width:6rem"><col style="width:6rem"><col style="width:6rem"><col style="width:6rem"><col style="width:12rem"><col></colgroup><thead><tr><th>Source</th><th>State</th><th>Classified</th><th>Reported</th><th>Suppressed</th><th>Pending</th><th>Last event</th><th>Latest evidence</th></tr></thead><tbody>`); err != nil {
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
				suppressedCell := buildSuppressedCell(row.Suppressed, row.SuppressionBreakdown)
				if _, err := fmt.Fprintf(w,
					`<tr><td>%s</td><td><span class="badge %s">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
					html.EscapeString(row.Source),
					pipelineStateBadgeClass(row.State),
					html.EscapeString(row.State),
					strconv.Itoa(row.Classified),
					strconv.Itoa(row.Reported),
					suppressedCell,
					strconv.Itoa(row.Pending),
					lastEventCell,
					latestEvidence,
				); err != nil {
					return err
				}
			}
			t := view.Total
			totalSuppressedCell := buildSuppressedCell(t.Suppressed, t.SuppressionBreakdown)
			if _, err := fmt.Fprintf(w,
				`</tbody><tfoot><tr><th>%s</th><th><span class="badge %s">%s</span></th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></tfoot></table></div></div>`,
				html.EscapeString(t.Source),
				pipelineStateBadgeClass(t.State),
				html.EscapeString(t.State),
				strconv.Itoa(t.Classified),
				strconv.Itoa(t.Reported),
				totalSuppressedCell,
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
	case "nginx_http_error":
		return "nginx"
	default:
		return ""
	}
}
