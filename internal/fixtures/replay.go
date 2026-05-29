package fixtures

import (
	"context"
	"fmt"
	"math/rand"
	"time"
)

// ReplayEngine provides a deterministic offline stream of API responses.
type ReplayEngine struct {
	fixtures map[string]SanitizedFixture
	metadata ReplayMetadata
	cursor   int
	rng      *rand.Rand
}

func NewReplayEngine(fixtures []SanitizedFixture, metadata ReplayMetadata) *ReplayEngine {
	fMap := make(map[string]SanitizedFixture)
	for _, f := range fixtures {
		fMap[f.SourceFixtureID] = f
	}

	return &ReplayEngine{
		fixtures: fMap,
		metadata: metadata,
		cursor:   0,
		rng:      rand.New(rand.NewSource(42)), // Deterministic seed
	}
}

type ReplayResult struct {
	Response SanitizedFixture
	Error    error
	Latency  time.Duration
}

// Next returns the next step in the replay sequence.
func (e *ReplayEngine) Next(ctx context.Context) (ReplayResult, error) {
	if e.cursor >= len(e.metadata.Ordering) {
		return ReplayResult{}, ioEOF()
	}

	fixtureID := e.metadata.Ordering[e.cursor]
	e.cursor++

	fixture, ok := e.fixtures[fixtureID]
	if !ok {
		return ReplayResult{}, fmt.Errorf("%w: %s", ErrFixtureNotFound, fixtureID)
	}

	// Validate integrity before replay
	if err := ValidateIntegrity(fixture); err != nil {
		return ReplayResult{}, err
	}

	// Simulate latency
	latency := e.metadata.LatencySimulation

	// Check for injected failures
	var injectedErr error
	for _, trigger := range e.metadata.FailureInjections {
		if trigger.FixtureID == fixtureID {
			if e.rng.Float64() < trigger.Chance {
				injectedErr = mapFailureType(trigger.Type)
				break
			}
		}
	}

	return ReplayResult{
		Response: fixture,
		Error:    injectedErr,
		Latency:  latency,
	}, nil
}

func mapFailureType(t FailureType) error {
	switch t {
	case FailTimeout:
		return ErrInjectedTimeout
	case FailRateLimit:
		return ErrInjectedRateLimit
	case FailTransient:
		return ErrInjectedTransient
	case FailMalformed:
		return ErrMalformedResponse
	case FailConnectionReset:
		return ErrConnectionReset
	case FailPartialPayload:
		return ErrPartialPayload
	default:
		return nil
	}
}

// ioEOF is a helper to avoid importing "io" just for EOF if we want to be minimal.
// But standard library is fine, so let's just use errors.New("EOF") or similar.
func ioEOF() error {
	return fmt.Errorf("EOF")
}
