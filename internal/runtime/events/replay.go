package events

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
)

var ErrInvalidCheckpoint = errors.New("runtime checkpoint invalid")

// StateReplayer can be implemented by components that can reconstruct their state from events.
type StateReplayer interface {
	ApplyEvent(ctx context.Context, event Event) error
}

type CheckpointReplayer interface {
	StateReplayer
	RestoreCheckpoint(ctx context.Context, checkpoint Checkpoint) error
}

type ReplayOptions struct {
	CheckpointName                      string
	AllowGenesisReplayWithoutCheckpoint bool
	UntilSequence                       uint64
	UntilTime                           time.Time
}

type ReplayResult struct {
	EventsApplied        uint64
	StartedAfterSequence uint64
	FinalSequence        uint64
	UsedCheckpoint       bool
}

func Replay(ctx context.Context, store EventStore, scopeID string, replayer StateReplayer) error {
	_, err := ReplayWithOptions(ctx, store, scopeID, replayer, ReplayOptions{})
	return err
}

func ReplayWithOptions(ctx context.Context, store EventStore, scopeID string, replayer StateReplayer, opts ReplayOptions) (ReplayResult, error) {
	var res ReplayResult
	var seq uint64

	if opts.CheckpointName != "" {
		if cps, ok := store.(CheckpointStore); ok {
			checkpoint, err := loadValidCheckpoint(ctx, cps, scopeID, opts.CheckpointName)
			switch {
			case err == nil:
				cr, ok := replayer.(CheckpointReplayer)
				if !ok {
					return res, apperr.New("events.Replay", "checkpoint replay requested but replayer cannot restore checkpoints")
				}
				if err := cr.RestoreCheckpoint(ctx, checkpoint); err != nil {
					return res, err
				}
				seq = checkpoint.Sequence
				res.StartedAfterSequence = seq
				res.UsedCheckpoint = true
			case errors.Is(err, ErrCheckpointNotFound):
				if !opts.AllowGenesisReplayWithoutCheckpoint {
					return res, err
				}
			case errors.Is(err, ErrInvalidCheckpoint):
				if !opts.AllowGenesisReplayWithoutCheckpoint {
					return res, err
				}
			default:
				return res, err
			}
		}
	}

	for {
		evs, err := store.List(ctx, scopeID, seq)
		if err != nil {
			return res, err
		}
		if len(evs) == 0 {
			break
		}

		for _, ev := range evs {
			if opts.UntilSequence > 0 && ev.Sequence > opts.UntilSequence {
				res.FinalSequence = seq
				return res, nil
			}
			if !opts.UntilTime.IsZero() && ev.Timestamp.After(opts.UntilTime) {
				res.FinalSequence = seq
				return res, nil
			}

			// Sequence continuity check
			if seq > 0 && ev.Sequence != seq+1 {
				// We allow seq=0 if we didn't use a checkpoint, but if we did,
				// seq should match the checkpoint sequence, and the first event
				// from List(seq) should be seq+1.
				// Wait, List(ctx, scopeID, seq) returns events AFTER seq.
				// So ev.Sequence MUST be > seq.
				// If it's not seq+1, we have a gap.
				if ev.Sequence <= seq {
					return res, apperr.Newf("events.Replay", "duplicate or backward sequence detected: current=%d next=%d", seq, ev.Sequence)
				}
				// We don't strictly enforce seq+1 yet because some systems might have logical gaps,
				// but for event sourcing it's usually mandatory.
				// For now, let's log it or return an error if it's a gap.
				return res, apperr.Newf("events.Replay", "sequence gap detected: current=%d next=%d", seq, ev.Sequence)
			}

			if err := replayer.ApplyEvent(ctx, ev); err != nil {
				return res, err
			}
			seq = ev.Sequence
			res.EventsApplied++
		}
	}
	res.FinalSequence = seq
	return res, nil
}

func loadValidCheckpoint(ctx context.Context, store CheckpointStore, scopeID string, name string) (Checkpoint, error) {
	var sawCheckpoint bool
	var invalidFound bool

	checkpoint, err := store.LatestCheckpoint(ctx, scopeID, name)
	if err == nil {
		sawCheckpoint = true
		if err := validateReplayCheckpoint(scopeID, name, checkpoint); err == nil {
			return checkpoint, nil
		} else {
			invalidFound = true
		}
	}

	if listStore, ok := store.(interface {
		ListCheckpoints(ctx context.Context, scopeID string, name string, limit int) ([]Checkpoint, error)
	}); ok {
		checkpoints, listErr := listStore.ListCheckpoints(ctx, scopeID, name, 0)
		if listErr != nil {
			return Checkpoint{}, listErr
		}
		for _, cp := range checkpoints {
			sawCheckpoint = true
			if err := validateReplayCheckpoint(scopeID, name, cp); err == nil {
				return cp, nil
			} else {
				invalidFound = true
			}
		}
	}

	if sawCheckpoint && invalidFound {
		return Checkpoint{}, apperr.Wrap("events.Replay", ErrInvalidCheckpoint)
	}
	return Checkpoint{}, ErrCheckpointNotFound
}

func validateReplayCheckpoint(expectedScopeID, expectedName string, checkpoint Checkpoint) error {
	if checkpoint.ScopeID != expectedScopeID {
		return apperr.Newf("events.Replay", "checkpoint scope mismatch: expected %s got %s", expectedScopeID, checkpoint.ScopeID)
	}
	if checkpoint.Name != expectedName {
		return apperr.Newf("events.Replay", "checkpoint name mismatch: expected %s got %s", expectedName, checkpoint.Name)
	}
	if checkpoint.Sequence == 0 {
		return apperr.New("events.Replay", "checkpoint sequence must be positive")
	}
	if checkpoint.EventID <= 0 {
		return apperr.New("events.Replay", "checkpoint event_id must be positive")
	}
	if checkpoint.CreatedAt.IsZero() {
		return apperr.New("events.Replay", "checkpoint created_at must be set")
	}
	if len(checkpoint.State) == 0 || !json.Valid(checkpoint.State) {
		return apperr.New("events.Replay", "checkpoint state must be valid json")
	}
	var compacted bytes.Buffer
	if err := json.Compact(&compacted, checkpoint.State); err != nil {
		return apperr.Wrap("events.Replay", err)
	}
	if compacted.String() != string(checkpoint.State) {
		return apperr.New("events.Replay", "checkpoint state must be canonical json")
	}
	expected := checkpointReplayChecksum(checkpoint.Name, checkpoint.ScopeID, checkpoint.Sequence, checkpoint.EventID, checkpoint.State, checkpoint.Metadata, checkpoint.SchemaVersion, checkpoint.CreatedAt)
	if checkpoint.Checksum != expected {
		return apperr.Newf("events.Replay", "checkpoint checksum mismatch for %s/%s at sequence %d", checkpoint.ScopeID, checkpoint.Name, checkpoint.Sequence)
	}
	return nil
}

func checkpointReplayChecksum(name string, scopeID string, sequence uint64, eventID int64, state json.RawMessage, metadata map[string]any, schemaVersion int, createdAt time.Time) string {
	payload, _ := json.Marshal(struct {
		Name          string          `json:"name"`
		ScopeID       string          `json:"scope_id"`
		Sequence      uint64          `json:"sequence"`
		EventID       int64           `json:"event_id"`
		State         json.RawMessage `json:"state"`
		Metadata      map[string]any  `json:"metadata,omitempty"`
		SchemaVersion int             `json:"schema_version"`
		CreatedAt     string          `json:"created_at"`
	}{
		Name:          name,
		ScopeID:       scopeID,
		Sequence:      sequence,
		EventID:       eventID,
		State:         state,
		Metadata:      metadata,
		SchemaVersion: schemaVersion,
		CreatedAt:     createdAt.UTC().Format(time.RFC3339Nano),
	})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// TypedPayload returns the unmarshaled payload of the event.
func TypedPayload[T any](event Event) (T, error) {
	var payload T
	err := json.Unmarshal(event.Payload, &payload)
	return payload, err
}
