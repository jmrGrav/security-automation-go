package diagnostics

import (
	"time"

	"github.com/jm/security-automation-go/internal/runtime/models"
)

// ConsistencyReport provides detailed diagnostics of the runtime state.
type ConsistencyReport struct {
	Healthy   bool      `json:"healthy"`
	CheckTime time.Time `json:"check_time"`

	JournalEntries int                `json:"journal_entries"`
	LastEvent      *models.AuditEvent `json:"last_event,omitempty"`

	HasLock        bool   `json:"has_lock"`
	CircuitBreaker string `json:"breaker_state"`

	IncompleteRuns  []string `json:"incomplete_runs,omitempty"`
	IntegrityIssues []string `json:"integrity_issues,omitempty"`
}

type Validator struct{}

func New() *Validator {
	return &Validator{}
}

func (v *Validator) ValidateConsistency(events []models.AuditEvent, state models.RuntimeState) ConsistencyReport {
	report := ConsistencyReport{
		CheckTime:      time.Now().UTC(),
		JournalEntries: len(events),
		Healthy:        true,
	}

	if len(events) > 0 {
		report.LastEvent = &events[len(events)-1]
	}

	// Simple heuristic: if the last state says incomplete, mark as unhealthy
	if state.IncompleteBatchID != "" {
		report.Healthy = false
		report.IncompleteRuns = append(report.IncompleteRuns, state.IncompleteBatchID)
	}

	return report
}
