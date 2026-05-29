package stateful

import (
	"math/rand"
	"time"
)

// AddJitter adds a random variation to a duration.
func AddJitter(base time.Duration, jitterFactor float64) time.Duration {
	if jitterFactor <= 0 {
		return base
	}

	jitterRange := float64(base) * jitterFactor
	offset := (rand.Float64() * jitterRange) - (jitterRange / 2)

	return base + time.Duration(offset)
}
