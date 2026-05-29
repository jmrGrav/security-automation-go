package stateful

import "time"

type CooldownPolicy struct {
	RollbackDelay    time.Duration
	OscillationDelay time.Duration
	BreakerOpenDelay time.Duration
	ConvergenceDelay time.Duration
}

func DefaultCooldownPolicy() CooldownPolicy {
	return CooldownPolicy{
		RollbackDelay:    15 * time.Minute,
		OscillationDelay: 1 * time.Hour,
		BreakerOpenDelay: 5 * time.Minute,
		ConvergenceDelay: 10 * time.Minute,
	}
}
