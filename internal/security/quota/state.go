package quota

// State represents the operational quota posture for a provider.
type State string

const (
	Normal    State = "NORMAL"
	Warning   State = "WARNING"
	Throttled State = "THROTTLED"
	Exhausted State = "EXHAUSTED"
	Unknown   State = "UNKNOWN"
)
