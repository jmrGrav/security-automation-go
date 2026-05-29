// Package events defines passive telemetry payloads emitted by outer layers.
package events

import "time"

type SecurityEvent struct {
	Timestamp         time.Time      `json:"timestamp"`
	Source            string         `json:"source"`
	IP                string         `json:"ip,omitempty"`
	URI               string         `json:"uri,omitempty"`
	Hostname          string         `json:"hostname,omitempty"`
	RuleID            string         `json:"rule_id,omitempty"`
	AbuseType         string         `json:"abuse_type,omitempty"`
	RiskScore         int            `json:"risk_score,omitempty"`
	Confidence        float64        `json:"confidence,omitempty"`
	EnforcementStage  string         `json:"enforcement_stage,omitempty"`
	Propagated        bool           `json:"propagated"`
	AbuseIPDBReported bool           `json:"abuseipdb_reported"`
	CloudflareBanned  bool           `json:"cloudflare_banned"`
	SuppressionReason string         `json:"suppression_reason,omitempty"`
	Severity          string         `json:"severity"`
	Metadata          map[string]any `json:"metadata,omitempty"`
}
