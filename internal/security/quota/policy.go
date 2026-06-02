package quota

import "math"

// Classify maps a remaining-quota percentage into an operational state.
// The caller must already know whether the quota observation is valid.
func Classify(known bool, remainingPercent float64) State {
	if !known {
		return Unknown
	}
	if remainingPercent <= 0 {
		return Exhausted
	}
	if remainingPercent <= 5 {
		return Throttled
	}
	if remainingPercent <= 15 {
		return Warning
	}
	return Normal
}

// ClassifyObservation populates the state from the observation's known values.
func ClassifyObservation(obs Observation) Observation {
	if percent, ok := obs.remainingPercent(); ok {
		obs.PercentKnown = true
		obs.RemainingPercent = percent
		obs.State = Classify(true, percent)
		return obs
	}
	obs.State = Unknown
	return obs
}

func clampNonNegative(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	return v
}
