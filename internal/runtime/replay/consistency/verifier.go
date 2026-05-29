package consistency

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/runtime/events"
)

type Report struct {
	ScopeID            string `json:"scope_id"`
	EventCount         int    `json:"event_count"`
	FirstSequence      uint64 `json:"first_sequence"`
	LastSequence       uint64 `json:"last_sequence"`
	ChecksumChain      string `json:"checksum_chain"`
	ContinuityOK       bool   `json:"continuity_ok"`
	OrderingOK         bool   `json:"ordering_ok"`
	CheckpointsValid   bool   `json:"checkpoints_valid"`
	DivergenceDetected bool   `json:"divergence_detected"`
}

type Verifier struct {
	store interface {
		List(ctx context.Context, scopeID string, afterSequence uint64) ([]events.Event, error)
	}
	checkpoints interface {
		ListCheckpoints(ctx context.Context, scopeID string, name string, limit int) ([]events.Checkpoint, error)
	}
}

func NewVerifier(store interface {
	List(ctx context.Context, scopeID string, afterSequence uint64) ([]events.Event, error)
}, checkpoints interface {
	ListCheckpoints(ctx context.Context, scopeID string, name string, limit int) ([]events.Checkpoint, error)
}) *Verifier {
	return &Verifier{store: store, checkpoints: checkpoints}
}

func (v *Verifier) Verify(ctx context.Context, scopeID string, checkpointName string) (Report, error) {
	const op = "runtime.replay.consistency.Verifier.Verify"

	list, err := v.store.List(ctx, scopeID, 0)
	if err != nil {
		return Report{}, apperr.Wrap(op, err)
	}
	report := Report{
		ScopeID:      scopeID,
		EventCount:   len(list),
		ContinuityOK: true,
		OrderingOK:   true,
	}
	if len(list) == 0 {
		report.CheckpointsValid = true
		report.ChecksumChain = hex.EncodeToString(sha256.New().Sum(nil))
		return report, nil
	}

	report.FirstSequence = list[0].Sequence
	report.LastSequence = list[len(list)-1].Sequence

	expected := list[0].Sequence
	h := sha256.New()
	for i, event := range list {
		if event.Sequence != expected {
			report.ContinuityOK = false
		}
		if i > 0 {
			prev := list[i-1]
			if event.Sequence <= prev.Sequence || event.Timestamp.Before(prev.Timestamp) {
				report.OrderingOK = false
			}
		}
		expected = event.Sequence + 1
		appendEventHash(h, event)
	}
	report.ChecksumChain = hex.EncodeToString(h.Sum(nil))

	if v.checkpoints != nil {
		checkpoints, err := v.checkpoints.ListCheckpoints(ctx, scopeID, checkpointName, 0)
		if err != nil {
			return Report{}, apperr.Wrap(op, err)
		}
		report.CheckpointsValid = true
		for _, checkpoint := range checkpoints {
			if err := verifyCheckpointContinuity(checkpoint, list); err != nil {
				report.CheckpointsValid = false
				report.DivergenceDetected = true
				break
			}
		}
	} else {
		report.CheckpointsValid = true
	}

	if !report.ContinuityOK || !report.OrderingOK || !report.CheckpointsValid {
		report.DivergenceDetected = true
	}
	return report, nil
}

func appendEventHash(h interface{ Write([]byte) (int, error) }, event events.Event) {
	payload, _ := json.Marshal(struct {
		Sequence      uint64          `json:"sequence"`
		Timestamp     string          `json:"timestamp"`
		Category      events.Category `json:"category"`
		Type          string          `json:"type"`
		CorrelationID string          `json:"correlation_id"`
		CausalID      string          `json:"causal_id"`
		Actor         string          `json:"actor"`
		ScopeID       string          `json:"scope_id"`
		Payload       json.RawMessage `json:"payload"`
	}{
		Sequence:      event.Sequence,
		Timestamp:     event.Timestamp.UTC().Format("2006-01-02T15:04:05.999999999Z"),
		Category:      event.Category,
		Type:          event.Type,
		CorrelationID: event.CorrelationID,
		CausalID:      event.CausalID,
		Actor:         event.Actor,
		ScopeID:       event.ScopeID,
		Payload:       event.Payload,
	})
	_, _ = h.Write(payload)
}

func verifyCheckpointContinuity(checkpoint events.Checkpoint, list []events.Event) error {
	for _, event := range list {
		if event.Sequence == checkpoint.Sequence {
			return nil
		}
	}
	if checkpoint.Sequence == 0 {
		return nil
	}
	return fmt.Errorf("checkpoint sequence %d not found in event stream", checkpoint.Sequence)
}
