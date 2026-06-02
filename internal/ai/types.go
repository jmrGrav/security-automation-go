package ai

// SubjectType identifies the operator-owned item that will be explained.
type SubjectType string

const (
	SubjectTimelineEvent  SubjectType = "timeline_event"
	SubjectAuditEvent     SubjectType = "audit_event"
	SubjectProvider       SubjectType = "provider"
	SubjectIntelligence   SubjectType = "intelligence"
	SubjectTrustedNetwork SubjectType = "trusted_network"
	SubjectDiff           SubjectType = "diff"
	SubjectReplay         SubjectType = "replay"
	SubjectRecovery       SubjectType = "recovery"
	SubjectDrift          SubjectType = "drift"
)

// ExplainRequest is the read-only contract for a future explain request.
type ExplainRequest struct {
	SubjectType        SubjectType `json:"subject_type"`
	SubjectID          string      `json:"subject_id"`
	ProviderPreference string      `json:"provider_preference"`
	Context            string      `json:"context,omitempty"`
	ContextHash        string      `json:"context_hash,omitempty"`
	MaxContextBytes    int         `json:"max_context_bytes,omitempty"`
	MaxOutputTokens    int         `json:"max_output_tokens,omitempty"`
}

// ExplainResponse is the normalized response shape for future explain results.
type ExplainResponse struct {
	Provider     string `json:"provider"`
	Model        string `json:"model"`
	Cached       bool   `json:"cached"`
	QuotaState   string `json:"quota_state"`
	Explanation  string `json:"explanation"`
	InputTokens  int    `json:"input_tokens,omitempty"`
	OutputTokens int    `json:"output_tokens,omitempty"`
	TotalTokens  int    `json:"total_tokens,omitempty"`
	ContextHash  string `json:"context_hash"`
	AuditID      string `json:"audit_id"`
}
