package replay

import (
	"github.com/jm/security-automation-go/internal/runtime/models"
)

// ReplayManager can simulate a sequence of events to reconstruct historical states.
type ReplayManager struct {
	events []models.AuditEvent
}

func New(events []models.AuditEvent) *ReplayManager {
	return &ReplayManager{events: events}
}

// ReconstructState calculates what the RuntimeState should have been after the replayed events.
func (m *ReplayManager) ReconstructState() models.RuntimeState {
	var state models.RuntimeState

	for _, e := range m.events {
		switch e.Status {
		case "completed":
			state.LastRunID = e.RunID
			state.LastSuccessAt = e.Timestamp
			state.IncompleteBatchID = ""
		case "executing":
			state.IncompleteBatchID = e.BatchID
		case "failed":
			state.IncompleteBatchID = ""
		}
	}

	return state
}
