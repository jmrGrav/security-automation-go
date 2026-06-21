// Package classifier normalizes and classifies locally observed or replayed
// security events so Cloudflare-replayed events can be reasoned about with the
// same semantics as local detections.
package classifier

import (
	"time"

	"github.com/jm/security-automation-go/internal/security/risk"
)

type Event struct {
	IP                 string    `json:"ip"`
	URI                string    `json:"uri"`
	URIs               []string  `json:"uris,omitempty"`
	Hostname           string    `json:"hostname"`
	UserAgent          string    `json:"user_agent"`
	Action             string    `json:"action"`
	HTTPMethod         string    `json:"http_method,omitempty"`
	RuleID             string    `json:"rule_id"`
	RulesetID          string    `json:"ruleset_id,omitempty"`
	RuleName           string    `json:"rule_name"`
	Source             string    `json:"source"`
	Timestamp          time.Time `json:"timestamp"`
	RayID              string    `json:"ray_id,omitempty"`
	CountryName        string    `json:"country_name,omitempty"`
	ASNDescription     string    `json:"asn_description,omitempty"`
	EdgeResponseStatus int       `json:"edge_response_status,omitempty"`
	Hits               int       `json:"hits"`
	WindowSec          int       `json:"window_seconds"`

	// Ref is an optional block-page reference string (e.g. from the
	// OpenResty/Lua WAF bundle's waf_refs.jsonl) carried through to evidence
	// for exact-match correlation. It does not affect classification.
	Ref string `json:"ref,omitempty"`
}

type Classification struct {
	AbuseType        string   `json:"abuse_type"`
	RiskScore        int      `json:"risk_score"`
	Confidence       float64  `json:"confidence"`
	Categories       []string `json:"categories"`
	Evidence         []string `json:"evidence"`
	SuspectedLowConf bool     `json:"suspected_low_confidence"`
	EnforcementStage string   `json:"enforcement_stage"`
}

func Classify(event Event) Classification {
	uris := event.URIs
	if len(uris) == 0 && event.URI != "" {
		uris = []string{event.URI}
	}
	assessment := risk.Assess(risk.Event{
		IP:            event.IP,
		URIs:          uris,
		UserAgent:     event.UserAgent,
		Action:        event.Action,
		RuleID:        event.RuleID,
		RuleName:      event.RuleName,
		Source:        event.Source,
		Timestamp:     event.Timestamp,
		Hits:          event.Hits,
		WindowSeconds: event.WindowSec,
	})
	categories := mapCategories(assessment.AbuseType)

	return Classification{
		AbuseType:        assessment.AbuseType,
		RiskScore:        assessment.Score,
		Confidence:       assessment.Confidence,
		Categories:       categories,
		Evidence:         assessment.Evidence,
		SuspectedLowConf: assessment.Confidence < 0.70 || assessment.SuppressedLowSignal,
		EnforcementStage: assessment.Decision,
	}
}

func mapCategories(abuseType string) []string {
	switch abuseType {
	case risk.CategoryBenignBootstrap:
		return []string{}
	case risk.CategoryWordPressProbe:
		return []string{"Web App Attack", "Bad Web Bot"}
	case risk.CategoryScanner, risk.CategorySuspiciousProbe:
		return []string{"Bad Web Bot"}
	case risk.CategoryCredentialAttack:
		return []string{"Brute-Force", "Web App Attack"}
	case risk.CategoryExploitAttempt, risk.CategoryAppSecAttack, risk.CategoryConfirmedAbuse:
		return []string{"Web App Attack"}
	case risk.CategoryBenignProbe:
		return []string{"Bad Web Bot"}
	default:
		return []string{"Bad Web Bot"}
	}
}
