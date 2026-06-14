package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

func (s *Server) handleEvidenceDetailPage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()
	evidenceID := r.PathValue("id")
	if evidenceID == "" {
		if livePanelRequest(r) {
			renderEvidenceDetailPanelError(w, "Evidence ID is missing.", "/evidence")
			return
		}
		http.NotFound(w, r)
		return
	}
	if s.evidence == nil {
		if livePanelRequest(r) {
			renderEvidenceDetailPanelError(w, "Evidence store not available.", "/evidence")
			return
		}
		http.NotFound(w, r)
		return
	}
	ev, ok, err := s.evidence.Get(ctx, evidenceID)
	if err != nil {
		http.Error(w, fmt.Sprintf("error loading evidence: %v", err), http.StatusInternalServerError)
		return
	}
	if !ok {
		if livePanelRequest(r) {
			renderEvidenceDetailPanelError(w, "Evidence not found.", "/evidence")
			return
		}
		http.NotFound(w, r)
		return
	}
	view := buildEvidenceDetailView(ev)
	_ = EvidenceDetailPage(view).Render(ctx, w)
}

func renderEvidenceDetailPanelError(w http.ResponseWriter, message, fallback string) {
	if _, err := fmt.Fprintf(w, `<div data-live-panel-content data-live-panel-title="Evidence Detail"><div class="empty"><p>%s</p><a class="badge live" href="%s">Open full page</a></div></div>`, html.EscapeString(message), html.EscapeString(fallback)); err != nil {
		return
	}
}

func buildEvidenceDetailView(ev reporting.DecisionEvidence) EvidenceDetailView {
	return EvidenceDetailView{
		Evidence:          ev,
		GateResult:        evidenceGateResult(ev),
		DecisionResult:    evidenceDecisionResult(ev),
		ActionResult:      evidenceActionResult(ev),
		NormalizedJSON:    evidenceNormalizedJSON(ev),
		RawJSON:           evidenceRawJSON(ev),
		ProtectedSummary:  evidenceGateResult(ev),
		SuppressionReason: ev.SuppressionReason,
	}
}

func EvidenceDetailPage(view EvidenceDetailView) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Evidence Detail",
		Headline: "Evidence Detail",
		Subtitle: "Read-only view of a single processed security event.",
		Active:   "/evidence",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			ev := view.Evidence
			if _, err := fmt.Fprintf(w, `<div data-live-panel-content data-live-panel-title="Evidence Detail"><div class="panel"><div class="badges"><span class="badge healthy">%s</span><span class="badge">%s</span><span class="badge %s">%s</span></div>`,
				html.EscapeString(view.GateResult),
				html.EscapeString(view.DecisionResult),
				pipelineStateBadgeClass(stateForDetail(ev)),
				html.EscapeString(view.ActionResult),
			); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, `<h2 style="margin-top:.8rem">%s</h2><p class="muted">source: %s · timestamp: %s · suppression: %s</p><div class="kv">`,
				html.EscapeString(ev.EvidenceID),
				html.EscapeString(ev.Source),
				html.EscapeString(formatEventTimestamp(ev.Timestamp)),
				html.EscapeString(valueOrUnknown(view.SuppressionReason)),
			); err != nil {
				return err
			}

			rows := []keyValueRow{
				{Key: "IP", Value: ev.IP},
				{Key: "hostname", Value: ev.Hostname},
				{Key: "URI", Value: ev.URI},
				{Key: "abuse type", Value: ev.AbuseType},
				{Key: "decision", Value: ev.Decision},
				{Key: "gate result", Value: view.GateResult},
				{Key: "decision result", Value: view.DecisionResult},
				{Key: "action result", Value: view.ActionResult},
				{Key: "risk score", Value: fmt.Sprintf("%d", ev.RiskScore)},
				{Key: "confidence", Value: fmt.Sprintf("%.2f", ev.Confidence)},
				{Key: "suppression reason", Value: view.SuppressionReason},
			}
			for _, row := range rows {
				if _, err := fmt.Fprintf(w, `<div class="row"><span>%s</span><span>%s</span></div>`, html.EscapeString(row.Key), html.EscapeString(valueOrUnknown(row.Value))); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `</div></div>`); err != nil {
				return err
			}

			if _, err := fmt.Fprint(w, `<div class="panel"><h2>Normalized event</h2>`); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `<div class="json-toolbar"><button type="button" class="copy-button" data-copy-target="#normalized-json" data-copy-label="Normalized JSON copied">Copy JSON</button></div>`); err != nil {
				return err
			}
			if view.NormalizedJSON == "" {
				if _, err := fmt.Fprint(w, `<div class="empty">No normalized event payload available.</div>`); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintf(w, `<pre id="normalized-json" class="json-block">%s</pre>`, html.EscapeString(view.NormalizedJSON)); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `</div>`); err != nil {
				return err
			}

			if _, err := fmt.Fprint(w, `<div class="panel"><h2>Raw evidence JSON</h2><div class="json-toolbar"><button type="button" class="copy-button" data-copy-target="#raw-evidence-json" data-copy-label="Raw JSON copied">Copy JSON</button></div>`); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `<pre id="raw-evidence-json" class="json-block">`); err != nil {
				return err
			}
			if _, err := io.WriteString(w, html.EscapeString(view.RawJSON)); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `</pre></div></div></div>`); err != nil {
				return err
			}
			return nil
		}),
	})
}

func stateForDetail(ev reporting.DecisionEvidence) string {
	switch {
	case ev.Suppressed:
		return "suppressed"
	case ev.AbuseIPDBReported:
		return "reported"
	case ev.Decision == "report_pending":
		return "pending"
	default:
		return "active"
	}
}
