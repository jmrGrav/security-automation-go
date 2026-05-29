package replay

import (
	"strings"

	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/classifier"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

type Result struct {
	ReplayOK                  bool   `json:"replay_ok"`
	MismatchComment           bool   `json:"mismatch_comment"`
	MismatchDecision          bool   `json:"mismatch_decision"`
	MismatchHash              bool   `json:"mismatch_hash"`
	MissingContext            bool   `json:"missing_context"`
	VersionDrift              bool   `json:"version_drift"`
	ExpectedClassifierVersion string `json:"expected_classifier_version,omitempty"`
	ExpectedFormatterVersion  string `json:"expected_formatter_version,omitempty"`
	ExpectedPolicyVersion     string `json:"expected_policy_version,omitempty"`
	ExpectedComment           string `json:"expected_comment,omitempty"`
	ExpectedDecision          string `json:"expected_decision,omitempty"`
	ExpectedInputHash         string `json:"expected_input_hash,omitempty"`
	ExpectedDecisionHash      string `json:"expected_decision_hash,omitempty"`
}

func Verify(evidence reporting.DecisionEvidence) Result {
	source, ok := sourceFromEvidence(evidence.Source)
	if !ok || missingEventContext(evidence.NormalizedEvent) {
		return Result{MissingContext: true}
	}

	cls := classifier.Classify(evidence.NormalizedEvent)
	expectedComment := abuseformat.Build(abuseformat.Input{
		Source:     source,
		Hits:       evidence.NormalizedEvent.Hits,
		WindowSec:  evidence.NormalizedEvent.WindowSec,
		Action:     evidence.NormalizedEvent.Action,
		AbuseType:  cls.AbuseType,
		Categories: cls.Categories,
		RuleID:     normalizedRuleID(evidence.NormalizedEvent.RuleID),
		URIs:       normalizedURIs(evidence.NormalizedEvent),
		Confidence: cls.Confidence,
	})
	expectedDecision := deriveDecision(evidence, cls)
	expectedInputHash := computeInputHash(source, evidence.NormalizedEvent)
	expectedDecisionHash := computeDecisionHash(expectedComment, cls, expectedDecision, evidence.SuppressionReason)

	result := Result{
		ExpectedClassifierVersion: reporting.ClassifierVersion,
		ExpectedFormatterVersion:  reporting.FormatterVersion,
		ExpectedPolicyVersion:     reporting.PolicyVersion,
		ExpectedComment:           expectedComment,
		ExpectedDecision:          expectedDecision,
		ExpectedInputHash:         expectedInputHash,
		ExpectedDecisionHash:      expectedDecisionHash,
	}
	result.MismatchComment = expectedComment != evidence.Comment
	result.MismatchDecision = expectedDecision != evidence.Decision
	result.MismatchHash = expectedInputHash != evidence.InputHash || expectedDecisionHash != evidence.DecisionHash
	result.VersionDrift =
		(evidence.ClassifierVersion != "" && evidence.ClassifierVersion != reporting.ClassifierVersion) ||
			(evidence.FormatterVersion != "" && evidence.FormatterVersion != reporting.FormatterVersion) ||
			(evidence.PolicyVersion != "" && evidence.PolicyVersion != reporting.PolicyVersion)
	result.ReplayOK = !result.MismatchComment && !result.MismatchDecision && !result.MismatchHash && !result.MissingContext && !result.VersionDrift
	return result
}

func sourceFromEvidence(source string) (abuseformat.Source, bool) {
	switch strings.TrimSpace(source) {
	case "crowdsec_waf":
		return abuseformat.SourceCrowdSecWAF, true
	case "openresty_waf":
		return abuseformat.SourceOpenRestyWAF, true
	case "cloudflare_waf":
		return abuseformat.SourceCloudflareWAF, true
	default:
		return "", false
	}
}

func deriveDecision(evidence reporting.DecisionEvidence, cls classifier.Classification) string {
	if evidence.SuppressionReason != "" || evidence.Suppressed {
		return "suppressed"
	}
	if evidence.Reported {
		return "reported"
	}
	if cls.EnforcementStage == "observe_only" {
		return "observed"
	}
	return evidence.Decision
}

func missingEventContext(event classifier.Event) bool {
	return strings.TrimSpace(event.IP) == "" &&
		strings.TrimSpace(event.Hostname) == "" &&
		strings.TrimSpace(event.URI) == "" &&
		len(event.URIs) == 0 &&
		strings.TrimSpace(event.RuleID) == ""
}

func normalizedRuleID(id string) string {
	if strings.TrimSpace(id) == "" {
		return "unknown"
	}
	return id
}

func normalizedURIs(event classifier.Event) []string {
	if len(event.URIs) > 0 {
		return append([]string(nil), event.URIs...)
	}
	if strings.TrimSpace(event.URI) == "" {
		return nil
	}
	return []string{event.URI}
}

func computeInputHash(source abuseformat.Source, event classifier.Event) string {
	req := reporting.Request{Source: source, Event: event}
	return reporting.ReplayInputHash(req)
}

func computeDecisionHash(comment string, cls classifier.Classification, decision string, suppressionReason string) string {
	return reporting.ReplayDecisionHash(comment, cls, decision, suppressionReason)
}
