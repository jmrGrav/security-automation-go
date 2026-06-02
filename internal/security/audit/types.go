package audit

// AuditEntry represents a single security audit log record.
type AuditEntry struct {
	Timestamp    string `json:"timestamp"`
	ActorSession string `json:"actor_session,omitempty"`
	Source       string `json:"source,omitempty"`
	RemoteIP     string `json:"remote_ip,omitempty"`
	Action       string `json:"action"`
	Target       string `json:"target,omitempty"`
	Result       string `json:"result,omitempty"`
	Error        string `json:"error,omitempty"`
	Correlation  string `json:"correlation_id,omitempty"`
	EventID      string `json:"event_id,omitempty"`
}

// AuditSink is the interface for recording security events.
type AuditSink interface {
	Record(action string, fields map[string]string)
}

// AuditReader is the interface for reading back security events.
type AuditReader interface {
	Entries() []AuditEntry
}
