package chaos

import (
	"time"

	"github.com/jm/security-automation-go/internal/runtime/breaker"
)

// Scenario defines a specific failure injection test case.
type Scenario struct {
	ID           string       `json:"id" yaml:"id"`
	Description  string       `json:"description" yaml:"description"`
	Injections   []Injection  `json:"inject" yaml:"inject"`
	Expectations Expectations `json:"expect" yaml:"expect"`
}

type Injection struct {
	Type        string  `json:"type" yaml:"type"` // "transport", "execution", "runtime", "corruption"
	Target      string  `json:"target" yaml:"target"`
	Probability float64 `json:"probability" yaml:"probability"`
	ErrorCode   int     `json:"status_code,omitempty" yaml:"status_code,omitempty"`
}

type Expectations struct {
	BreakerState      *breaker.State `json:"breaker_state,omitempty" yaml:"breaker_state,omitempty"`
	MutationsExecuted *int           `json:"mutations_executed,omitempty" yaml:"mutations_executed,omitempty"`
	QuarantineCount   *int           `json:"quarantine_count,omitempty" yaml:"quarantine_count,omitempty"`
	MinJournalEntries *int           `json:"min_journal_entries,omitempty" yaml:"min_journal_entries,omitempty"`
	Success           *bool          `json:"success,omitempty" yaml:"success,omitempty"`
}

// Result captures the outcome of a chaos scenario run.
type Result struct {
	ScenarioID string        `json:"scenario_id"`
	Passed     bool          `json:"passed"`
	StartTime  time.Time     `json:"start_time"`
	Duration   time.Duration `json:"duration_ms"`
	Failures   []string      `json:"failures,omitempty"`
}
