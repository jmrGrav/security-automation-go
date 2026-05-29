package stateful

import (
	"math"
	"math/rand"
	"time"
)

// RetryPolicy defines exponential backoff parameters.
type RetryPolicy struct {
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	Jitter       float64
	MaxRetries   int
}

// CalculateDelay returns the wait time for a given retry attempt.
func (p RetryPolicy) CalculateDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return p.InitialDelay
	}

	delay := float64(p.InitialDelay) * math.Pow(p.Multiplier, float64(attempt))
	if delay > float64(p.MaxDelay) {
		delay = float64(p.MaxDelay)
	}

	if p.Jitter > 0 {
		jitterRange := delay * p.Jitter
		delay = delay - (jitterRange / 2) + (rand.Float64() * jitterRange)
	}

	return time.Duration(delay)
}

func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		InitialDelay: 5 * time.Second,
		MaxDelay:     15 * time.Minute,
		Multiplier:   2.0,
		Jitter:       0.1,
		MaxRetries:   10,
	}
}
