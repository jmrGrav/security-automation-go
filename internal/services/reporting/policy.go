package reporting

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/classifier"
	"github.com/jm/security-automation-go/internal/security/reputation"
)

func (s *Service) suppressionReason(req Request, cls classifier.Classification) string {
	if s.isProtected(req.Event.IP) {
		return "protected_target"
	}
	if cls.AbuseType == "benign_bootstrap" || cls.AbuseType == "benign_probe" {
		return "benign_signal"
	}
	if cls.Confidence < s.lowConfidence || cls.SuspectedLowConf {
		return "low_confidence"
	}
	if len(cls.Categories) == 0 {
		return "no_abuse_categories"
	}
	if s.gate.isDuplicate(req, cls) {
		return "duplicate_report"
	}
	return ""
}

// reputationLocalSignal maps a classifier.Classification to the
// reputation.LocalSignal the gate uses to decide whether external low/zero
// reputation should suppress this report outright (SignalWeak/SignalNone)
// or merely move it to investigation_shadow (SignalConfirmedHostile).
//
// Confirmed-hostile AbuseType values mirror classifier/risk's own hostile
// categories (exploit_attempt, appsec_attack, confirmed_abuse) — anything
// definitively assessed as an attack payload, not just a scanner/probe.
func reputationLocalSignal(cls classifier.Classification) reputation.LocalSignal {
	switch cls.AbuseType {
	case "benign_bootstrap", "benign_probe", "":
		return reputation.LocalSignal{Strength: reputation.SignalNone, AbuseType: cls.AbuseType}
	case "exploit_attempt", "appsec_attack", "confirmed_abuse":
		return reputation.LocalSignal{Strength: reputation.SignalConfirmedHostile, AbuseType: cls.AbuseType}
	default:
		return reputation.LocalSignal{Strength: reputation.SignalWeak, AbuseType: cls.AbuseType}
	}
}

func telemetrySource(source abuseformat.Source) string {
	switch source {
	case abuseformat.SourceCrowdSecWAF:
		return "crowdsec_waf"
	case abuseformat.SourceOpenRestyWAF:
		return "openresty_waf"
	default:
		return "cloudflare_waf"
	}
}

func eventURIs(event classifier.Event) []string {
	if len(event.URIs) > 0 {
		return append([]string(nil), event.URIs...)
	}
	if event.URI == "" {
		return nil
	}
	return []string{event.URI}
}

func ruleID(id string) string {
	if strings.TrimSpace(id) == "" {
		return "unknown"
	}
	return id
}

func recordCommentMetrics(source abuseformat.Source, event classifier.Event, comment string, cls classifier.Classification) {
	metrics.AbuseIPDBCommentGeneratedTotal.WithLabelValues(telemetrySource(source)).Inc()
	if strings.HasSuffix(comment, "…") {
		metrics.AbuseIPDBCommentTruncatedTotal.Inc()
	}
	if strings.TrimSpace(event.RuleID) == "" || len(eventURIs(event)) == 0 {
		metrics.AbuseIPDBCommentMissingFieldsTotal.Inc()
	}
	for _, category := range cls.Categories {
		metrics.AbuseIPDBCategoryMappingTotal.WithLabelValues(category).Inc()
	}
	if source == abuseformat.SourceCloudflareWAF {
		metrics.CloudflareEventsReplayedLocalTotal.Inc()
		metrics.CloudflareEventsClassifiedTotal.Inc()
		metrics.CloudflareLocalReplayConfidenceScore.Observe(cls.Confidence)
	}
}

func recordReportMetrics(source abuseformat.Source, cls classifier.Classification) {
	metrics.AbuseIPDBReportSourceTotal.WithLabelValues(telemetrySource(source)).Inc()
	if source == abuseformat.SourceCloudflareWAF {
		metrics.CloudflareEventsReportedAbuseIPDBTotal.Inc()
	}
	_ = cls
}

func categoryIDs(categories []string) string {
	ids := make([]string, 0, len(categories))
	for _, category := range categories {
		switch category {
		case "Bad Web Bot":
			ids = append(ids, "19")
		case "Brute-Force":
			ids = append(ids, "18")
		case "Web App Attack":
			ids = append(ids, "21")
		}
	}
	sort.Strings(ids)
	out := ids[:0]
	var prev string
	for _, id := range ids {
		if id == prev {
			continue
		}
		out = append(out, id)
		prev = id
	}
	return strings.Join(out, ",")
}

func severityFor(abuseType string) string {
	switch abuseType {
	case "benign_bootstrap", "benign_probe":
		return "info"
	case "suspicious_probe", "wordpress_probe":
		return "warning"
	case "exploit_attempt":
		return "high"
	case "confirmed_abuse":
		return "critical"
	default:
		return "warning"
	}
}

func fingerprint(req Request, cls classifier.Classification) string {
	sum := sha256.Sum256([]byte(string(req.Source) + "|" + req.Event.IP + "|" + strings.Join(eventURIs(req.Event), ",") + "|" + req.Event.RuleID + "|" + cls.AbuseType))
	return "report-" + hex.EncodeToString(sum[:8])
}

func executionID(req Request, cls classifier.Classification) string {
	return "exec-" + fingerprint(req, cls)
}

func decisionEvidenceID(req Request, cls classifier.Classification, suppressionReason string, now time.Time) string {
	sum := sha256.Sum256([]byte(
		string(req.Source) + "|" +
			req.Event.IP + "|" +
			strings.Join(eventURIs(req.Event), ",") + "|" +
			req.Event.RuleID + "|" +
			cls.AbuseType + "|" +
			suppressionReason + "|" +
			now.UTC().Format(time.RFC3339Nano),
	))
	return "report-ev-" + hex.EncodeToString(sum[:8])
}

func decisionKind(reported bool, suppressed bool) string {
	switch {
	case reported:
		return "reported"
	case suppressed:
		return "suppressed"
	default:
		return "observed"
	}
}

func evidenceInputHash(req Request) string {
	sum := sha256.Sum256([]byte(
		string(req.Source) + "|" +
			req.Event.IP + "|" +
			req.Event.Hostname + "|" +
			strings.Join(eventURIs(req.Event), ",") + "|" +
			req.Event.UserAgent + "|" +
			req.Event.Action + "|" +
			req.Event.RuleID + "|" +
			req.Event.RuleName + "|" +
			req.Event.Timestamp.UTC().Format(time.RFC3339Nano),
	))
	return hex.EncodeToString(sum[:])
}

func evidenceDecisionHash(comment string, cls classifier.Classification, decision string, suppressionReason string) string {
	sum := sha256.Sum256([]byte(
		comment + "|" +
			cls.AbuseType + "|" +
			strings.Join(cls.Categories, ",") + "|" +
			decision + "|" +
			suppressionReason,
	))
	return hex.EncodeToString(sum[:])
}
