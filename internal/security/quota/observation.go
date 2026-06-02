package quota

import "time"

// Observation is the normalized runtime view of a provider quota signal.
type Observation struct {
	Provider         string
	Plan             string
	QuotaSource      string
	Limit            float64
	Used             float64
	Remaining        float64
	LimitKnown       bool
	UsedKnown        bool
	RemainingKnown   bool
	RemainingPercent float64
	PercentKnown     bool
	ResetAt          time.Time
	ResetKnown       bool
	ObservedAt       time.Time
	State            State
	Notes            []string
}

func (o Observation) clone() Observation {
	cp := o
	if len(o.Notes) > 0 {
		cp.Notes = append([]string(nil), o.Notes...)
	}
	return cp
}

// Clone returns a deep copy safe for cross-package callers.
func (o Observation) Clone() Observation {
	return o.clone()
}

func (o Observation) remainingPercent() (float64, bool) {
	if o.PercentKnown {
		return o.RemainingPercent, true
	}
	if !o.LimitKnown || !o.RemainingKnown || o.Limit <= 0 {
		return 0, false
	}
	return (clampNonNegative(o.Remaining) / o.Limit) * 100, true
}
