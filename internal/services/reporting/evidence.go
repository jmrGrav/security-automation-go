package reporting

import (
	"context"
	"time"

	"github.com/jm/security-automation-go/internal/security/classifier"
)

type DecisionEvidence struct {
	EvidenceID        string           `json:"evidence_id"`
	Timestamp         time.Time        `json:"timestamp"`
	Source            string           `json:"source"`
	IP                string           `json:"ip,omitempty"`
	Hostname          string           `json:"hostname,omitempty"`
	URI               string           `json:"uri,omitempty"`
	URIs              []string         `json:"uri_list,omitempty"`
	RuleID            string           `json:"rule_id,omitempty"`
	AbuseType         string           `json:"abuse_type,omitempty"`
	Categories        []string         `json:"categories,omitempty"`
	RiskScore         int              `json:"risk_score,omitempty"`
	Confidence        float64          `json:"confidence,omitempty"`
	EnforcementStage  string           `json:"enforcement_stage,omitempty"`
	Decision          string           `json:"decision,omitempty"`
	Comment           string           `json:"comment,omitempty"`
	Reported          bool             `json:"reported"`
	Suppressed        bool             `json:"suppressed"`
	SuppressionReason string           `json:"suppression_reason,omitempty"`
	AbuseIPDBReported bool             `json:"abuseipdb_reported"`
	CloudflareBanned  bool             `json:"cloudflare_banned"`
	IdempotencyKey    string           `json:"idempotency_key,omitempty"`
	DedupKey          string           `json:"dedup_key,omitempty"`
	LastReportedAt    time.Time        `json:"last_reported_at,omitempty"`
	NextAllowedAt     time.Time        `json:"next_allowed_at,omitempty"`
	InputHash         string           `json:"input_hash,omitempty"`
	DecisionHash      string           `json:"decision_hash,omitempty"`
	ClassifierVersion string           `json:"classifier_version,omitempty"`
	FormatterVersion  string           `json:"formatter_version,omitempty"`
	PolicyVersion     string           `json:"decision_policy_version,omitempty"`
	NormalizedEvent   classifier.Event `json:"normalized_event,omitempty"`
	Metadata          map[string]any   `json:"metadata,omitempty"`
}

type EvidenceSearchOptions struct {
	IP                string
	Source            string
	Decision          string
	SuppressionReason string
	From              time.Time
	To                time.Time
	Limit             int
	Offset            int
}

type EvidenceStore interface {
	Append(ctx context.Context, evidence DecisionEvidence) error
	List(ctx context.Context, limit int) ([]DecisionEvidence, error)
	Get(ctx context.Context, evidenceID string) (DecisionEvidence, bool, error)
	Search(ctx context.Context, opts EvidenceSearchOptions) ([]DecisionEvidence, error)
}

const (
	ClassifierVersion = "classifier/v1"
	FormatterVersion  = "abuseformat/v1"
	PolicyVersion     = "reporting-policy/v1"
)
