package reporting

import "time"

type EvidenceExplanation struct {
	EvidenceID        string    `json:"evidence_id"`
	CreatedAt         time.Time `json:"created_at"`
	Decision          string    `json:"decision"`
	Reason            string    `json:"reason"`
	Source            string    `json:"source"`
	IP                string    `json:"ip"`
	Hostname          string    `json:"hostname,omitempty"`
	URIs              []string  `json:"uri_list,omitempty"`
	AbuseType         string    `json:"abuse_type,omitempty"`
	RiskScore         int       `json:"risk_score,omitempty"`
	Confidence        float64   `json:"confidence,omitempty"`
	Categories        []string  `json:"categories,omitempty"`
	Comment           string    `json:"comment,omitempty"`
	LastReportedAt    time.Time `json:"last_reported_at,omitempty"`
	NextAllowedAt     time.Time `json:"next_allowed_at,omitempty"`
	SuppressionReason string    `json:"suppression_reason,omitempty"`
	InputHash         string    `json:"input_hash,omitempty"`
	DecisionHash      string    `json:"decision_hash,omitempty"`
}

func ExplainEvidence(evidence DecisionEvidence) EvidenceExplanation {
	reason := evidence.SuppressionReason
	if reason == "" {
		reason = "reported: " + evidence.AbuseType
	} else {
		reason = "suppressed: " + reason
	}
	return EvidenceExplanation{
		EvidenceID:        evidence.EvidenceID,
		CreatedAt:         evidence.Timestamp,
		Decision:          evidence.Decision,
		Reason:            reason,
		Source:            evidence.Source,
		IP:                evidence.IP,
		Hostname:          evidence.Hostname,
		URIs:              evidence.URIs,
		AbuseType:         evidence.AbuseType,
		RiskScore:         evidence.RiskScore,
		Confidence:        evidence.Confidence,
		Categories:        evidence.Categories,
		Comment:           evidence.Comment,
		LastReportedAt:    evidence.LastReportedAt,
		NextAllowedAt:     evidence.NextAllowedAt,
		SuppressionReason: evidence.SuppressionReason,
		InputHash:         evidence.InputHash,
		DecisionHash:      evidence.DecisionHash,
	}
}
