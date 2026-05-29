package httpclient

import "time"

type Backoff interface {
	Duration(attempt int) time.Duration
}

type ExponentialBackoff struct {
	base time.Duration
	max  time.Duration
}

func NewExponentialBackoff(base, max time.Duration) ExponentialBackoff {
	if base <= 0 {
		base = time.Second
	}
	if max < base {
		max = base
	}
	return ExponentialBackoff{base: base, max: max}
}

func (b ExponentialBackoff) Duration(attempt int) time.Duration {
	if attempt <= 1 {
		return b.base
	}

	delay := b.base
	for i := 1; i < attempt; i++ {
		if delay >= b.max/2 {
			return b.max
		}
		delay *= 2
	}
	if delay > b.max {
		return b.max
	}
	return delay
}
