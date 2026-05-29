package bus

import (
	"context"
	"log/slog"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

// EventBus handles internal system signals and structured logging.
type EventBus struct {
	logger *slog.Logger
	newBus *events.Bus
}

func New(logger *slog.Logger, newBus *events.Bus) *EventBus {
	return &EventBus{logger: logger, newBus: newBus}
}

func (b *EventBus) Emit(eventType models.EventType, runID string, metadata map[string]interface{}) {
	b.EmitContext(context.Background(), eventType, runID, metadata)
}

func (b *EventBus) EmitContext(ctx context.Context, eventType models.EventType, runID string, metadata map[string]interface{}) {
	if b.logger == nil {
		return
	}

	event := models.SystemEvent{
		Type:      eventType,
		Timestamp: time.Now().UTC(),
		RunID:     runID,
		Metadata:  metadata,
	}

	b.logger.Info("system_event",
		"event", event.Type,
		"run_id", event.RunID,
		"ts", event.Timestamp,
		"metadata", event.Metadata,
	)

	if b.newBus != nil {
		// Attempt to map to new event categories
		category := events.CategoryLifecycle
		// Simple mapping for now
		_ = b.newBus.Publish(ctx, category, string(eventType), "default", runID, metadata)
	}
}
