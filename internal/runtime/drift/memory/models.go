package memory

import (
	"time"
)

type Trend string

const (
	TrendImproving Trend = "improving"
	TrendStable    Trend = "stable"
	TrendWorsening Trend = "worsening"
)

// DriftMemory tracks the historical behavior of a specific drift pattern.
type DriftMemory struct {
	Fingerprint   string    `json:"fingerprint"`
	FirstSeenAt   time.Time `json:"first_seen_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	Occurrences   int       `json:"occurrences"`
	LastScopeID   string    `json:"last_scope_id"`
	LastLeaderID  string    `json:"last_leader_id"`
	SeverityTrend Trend     `json:"severity_trend"`
	LastRiskScore float64   `json:"last_risk_score"`
}

// Confidence estimates the likely source of a drift.
type Confidence struct {
	ProviderInstability float64 `json:"provider_instability"` // 0.0 to 1.0
	HostileProbability  float64 `json:"hostile_probability"`
	OperatorProbability float64 `json:"operator_probability"`
}
