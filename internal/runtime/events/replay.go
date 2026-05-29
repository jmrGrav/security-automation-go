package events

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
)

// StateReplayer can be implemented by components that can reconstruct their state from events.
type StateReplayer interface {
	ApplyEvent(ctx context.Context, event Event) error
}

type CheckpointReplayer interface {
	StateReplayer
	RestoreCheckpoint(ctx context.Context, checkpoint Checkpoint) error
}

type ReplayOptions struct {
	CheckpointName string
	UntilSequence  uint64
	UntilTime      time.Time
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
			checkpoint, err := cps.LatestCheckpoint(ctx, scopeID, opts.CheckpointName)
			switch {
			case err == nil:
				if cr, ok := replayer.(CheckpointReplayer); ok {
					if err := cr.RestoreCheckpoint(ctx, checkpoint); err != nil {
						return res, err
					}
					seq = checkpoint.Sequence
					res.StartedAfterSequence = seq
					res.UsedCheckpoint = true
				}
			case err == ErrCheckpointNotFound:
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

// TypedPayload returns the unmarshaled payload of the event.
func TypedPayload[T any](event Event) (T, error) {
	var payload T
	err := json.Unmarshal(event.Payload, &payload)
	return payload, err
}
