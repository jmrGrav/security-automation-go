package fixtures

import (
	"time"
)

type ReplayMode string

const (
	ModeSequential ReplayMode = "sequential"
	ModeParallel   ReplayMode = "parallel" // Parallel-safe if deterministic order is not required per-item
)

// ReplayMetadata defines how a set of sanitized fixtures should be replayed.
// It allows simulating network conditions and API failures.
type ReplayMetadata struct {
	ReplayID           string           `json:"replay_id"`
	FixtureIDs         []string         `json:"fixture_ids"`
	Ordering           []string         `json:"ordering"` // IDs in execution order
	PaginationSequence bool             `json:"pagination_sequence"`
	ExpectedFailures   map[string]error `json:"-"` // Not serialized directly
	FailureInjections  []FailureTrigger `json:"failure_injections"`
	LatencySimulation  time.Duration    `json:"latency_simulation"`
	SchemaExpectations string           `json:"schema_expectations"`
	ReplayMode         ReplayMode       `json:"replay_mode"`
}

type FailureType string

const (
	FailTimeout         FailureType = "timeout"
	FailRateLimit       FailureType = "rate_limit"
	FailTransient       FailureType = "transient"
	FailMalformed       FailureType = "malformed"
	FailConnectionReset FailureType = "connection_reset"
	FailPartialPayload  FailureType = "partial_payload"
)

type FailureTrigger struct {
	FixtureID string      `json:"fixture_id"`
	Type      FailureType `json:"type"`
	Chance    float64     `json:"chance"` // 0.0 to 1.0
}
