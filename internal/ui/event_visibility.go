package ui

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/detect"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

func (s *Server) latestEvidenceForSource(ctx context.Context, source string) (reporting.DecisionEvidence, bool) {
	if s == nil || s.evidence == nil {
		return reporting.DecisionEvidence{}, false
	}
	rows, err := s.evidence.Search(ctx, reporting.EvidenceSearchOptions{Source: source, Limit: 1})
	if err != nil || len(rows) == 0 {
		return reporting.DecisionEvidence{}, false
	}
	return rows[0], true
}

func pipelineSourceState(det detect.Result, count int) string {
	switch {
	case !det.Installed && !det.Configured:
		return "disabled"
	case count > 0:
		return "active"
	case det.Configured:
		return "no events yet"
	case det.Healthy:
		return "active"
	default:
		return "disabled"
	}
}

func pipelineStateBadgeClass(state string) string {
	switch state {
	case "active":
		return "healthy"
	case "no events yet":
		return "warning"
	case "disabled":
		return "badge"
	case "unavailable":
		return "error"
	default:
		return "badge"
	}
}

func evidenceDetailURL(evidenceID string) string {
	if strings.TrimSpace(evidenceID) == "" {
		return ""
	}
	return "/evidence/" + url.PathEscape(strings.TrimSpace(evidenceID))
}

func evidenceDetailLinkHTML(evidenceID string) string {
	href := evidenceDetailURL(evidenceID)
	if href == "" {
		return `<span class="muted">unavailable</span>`
	}
	return compactLinkCopyHTML(href, evidenceID, evidenceID, "Evidence Detail", "Evidence ID copied", 14)
}

func evidenceGateResult(ev reporting.DecisionEvidence) string {
	switch ev.SuppressionReason {
	case "protected_target", "allowlist", "rfc1918_loopback", "cloudflare_ip":
		return "suppressed by protected gate"
	case "":
		return "passed"
	default:
		return "passed"
	}
}

func evidenceDecisionResult(ev reporting.DecisionEvidence) string {
	switch {
	case ev.AbuseIPDBReported:
		return "reported"
	case ev.Suppressed:
		return "suppressed"
	case strings.TrimSpace(ev.Decision) != "":
		return ev.Decision
	default:
		return "observed"
	}
}

func evidenceActionResult(ev reporting.DecisionEvidence) string {
	switch {
	case ev.CloudflareBanned:
		return "cloudflare ban applied"
	case ev.AbuseIPDBReported:
		return "abuseipdb report sent"
	case ev.Suppressed:
		return "suppressed"
	case strings.TrimSpace(ev.Decision) != "":
		return ev.Decision
	default:
		return "observed"
	}
}

func evidenceNormalizedJSON(ev reporting.DecisionEvidence) string {
	data, err := json.MarshalIndent(ev.NormalizedEvent, "", "  ")
	if err != nil {
		return ""
	}
	if string(data) == "{}" {
		return ""
	}
	return string(data)
}

func evidenceRawJSON(ev reporting.DecisionEvidence) string {
	data, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return ""
	}
	return string(data)
}

func formatEventTimestamp(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.UTC().Format(time.RFC3339)
}
