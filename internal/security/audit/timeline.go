package audit

// TimelineEvent represents a security event projected for the operator timeline.
type TimelineEvent struct {
	Timestamp      string `json:"timestamp"`
	Scope          string `json:"scope"`
	EventType      string `json:"event_type"`
	Severity       string `json:"severity"`
	CorrelationID  string `json:"correlation_id,omitempty"`
	EvidenceID     string `json:"evidence_id,omitempty"`
	ReplaySequence string `json:"replay_sequence,omitempty"`
	ActorSource    string `json:"actor_source"`
	Action         string `json:"action"`
	Target         string `json:"target,omitempty"`
	Result         string `json:"result,omitempty"`
	Summary        string `json:"summary,omitempty"`
}
