package reducer

import (
	"encoding/json"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

type TransitionInput struct {
	From         models.RuntimeStatus
	To           models.RuntimeStatus
	At           time.Time
	EpochID      string
	FencingToken int64
	LeaseID      string
}

func ApplyLifecycleTransition(state models.RuntimeState, input TransitionInput) models.RuntimeState {
	now := input.At.UTC()
	state.Lifecycle.Status = input.To
	state.Lifecycle.LastUpdatedAt = now
	if input.From == models.StatusIdle && state.Lifecycle.StartedAt.IsZero() {
		state.Lifecycle.StartedAt = now
	}

	if input.EpochID != "" {
		state.CurrentEpoch.ID = input.EpochID
		state.CurrentEpoch.Generation = input.FencingToken
		if state.CurrentEpoch.CreatedAt.IsZero() {
			state.CurrentEpoch.CreatedAt = now
		}
	}

	if input.LeaseID != "" {
		lease := &models.Lease{
			ID:           input.LeaseID,
			Action:       "reconcile",
			EpochID:      input.EpochID,
			FencingToken: input.FencingToken,
			CreatedAt:    now,
		}
		if input.To == models.StatusRollingBack {
			lease.Action = "rollback"
			state.ActiveRollbackLease = lease
		} else {
			state.ActiveLease = lease
		}
	}

	switch input.To {
	case models.StatusIdle, models.StatusConverged, models.StatusFailed:
		state.ActiveLease = nil
		state.ActiveRollbackLease = nil
		state.ActiveRollbackID = ""
	case models.StatusRollingBack:
		if input.EpochID != "" {
			state.ActiveRollbackID = input.EpochID
		}
	}

	return state
}

func ApplyEvent(state models.RuntimeState, event events.Event) (models.RuntimeState, error) {
	switch event.Type {
	case events.TypeLifecycleTransition:
		var payload events.LifecycleTransitionPayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return state, err
		}
		metadata := event.Metadata
		return ApplyLifecycleTransition(state, TransitionInput{
			From:         models.RuntimeStatus(payload.From),
			To:           models.RuntimeStatus(payload.To),
			At:           event.Timestamp,
			EpochID:      metadataString(metadata, "epoch_id"),
			FencingToken: metadataInt64(metadata, "fencing_token"),
			LeaseID:      metadataString(metadata, "lease_id"),
		}), nil
	case events.TypeLeaseAcquired:
		var payload events.LeaseAcquiredPayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return state, err
		}
		lease := &models.Lease{
			ID:           payload.LeaseID,
			Action:       payload.Action,
			EpochID:      payload.EpochID,
			Owner:        payload.Owner,
			FencingToken: payload.FencingToken,
			ExpiresAt:    payload.ExpiresAt,
			CreatedAt:    event.Timestamp.UTC(),
		}
		if payload.Action == "rollback" {
			state.ActiveRollbackLease = lease
			if payload.EpochID != "" {
				state.ActiveRollbackID = payload.EpochID
			}
		} else {
			state.ActiveLease = lease
		}
		return state, nil
	case events.TypeFencingTokenIssued:
		var payload events.FencingTokenIssuedPayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return state, err
		}
		state.CurrentEpoch.ID = payload.EpochID
		state.CurrentEpoch.Generation = payload.FencingToken
		if state.CurrentEpoch.CreatedAt.IsZero() {
			state.CurrentEpoch.CreatedAt = event.Timestamp.UTC()
		}
		return state, nil
	case events.TypeRollbackStarted:
		var payload events.RollbackPayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return state, err
		}
		state.ActiveRollbackID = payload.RollbackID
		return state, nil
	case events.TypeRollbackCompleted, events.TypeRollbackFailed:
		state.ActiveRollbackID = ""
		state.ActiveRollbackLease = nil
		return state, nil
	default:
		return state, nil
	}
}

func metadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, ok := metadata[key]
	if !ok {
		return ""
	}
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

func metadataInt64(metadata map[string]any, key string) int64 {
	if metadata == nil {
		return 0
	}
	value, ok := metadata[key]
	if !ok {
		return 0
	}
	switch v := value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case json.Number:
		n, err := v.Int64()
		if err == nil {
			return n
		}
	}
	return 0
}
