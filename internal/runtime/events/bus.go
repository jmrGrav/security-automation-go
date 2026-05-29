package events

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
)

type Subscriber func(ctx context.Context, event Event) error

type Bus struct {
	store       EventStore
	subscribers map[Category][]Subscriber
	mu          sync.RWMutex
	logger      *slog.Logger
}

func NewBus(store EventStore, logger *slog.Logger) *Bus {
	return &Bus{
		store:       store,
		subscribers: make(map[Category][]Subscriber),
		logger:      logger,
	}
}

func (b *Bus) Subscribe(category Category, sub Subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribers[category] = append(b.subscribers[category], sub)
}

func (b *Bus) PublishEvent(ctx context.Context, req PublishRequest) (Event, error) {
	const op = "runtime.events.Bus.PublishEvent"

	payloadBytes, err := json.Marshal(req.Payload)
	if err != nil {
		return Event{}, apperr.Wrap(op, err)
	}

	event := Event{
		UID:           req.UID,
		Timestamp:     req.Timestamp.UTC(),
		Category:      req.Category,
		Type:          req.Type,
		CorrelationID: req.CorrelationID,
		CausalID:      req.CausalID,
		Actor:         req.Actor,
		ScopeID:       req.ScopeID,
		Payload:       payloadBytes,
		Metadata:      cloneMetadata(req.Metadata),
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Actor == "" {
		event.Actor = "system"
	}

	if err := b.store.Append(ctx, &event); err != nil {
		return Event{}, apperr.Wrap(op, err)
	}

	b.mu.RLock()
	subs := append([]Subscriber(nil), b.subscribers[event.Category]...)
	b.mu.RUnlock()
	for _, sub := range subs {
		if err := sub(ctx, event); err != nil {
			return Event{}, apperr.Wrap(op, err)
		}
	}

	if b.logger != nil {
		b.logger.Debug("event_published",
			"scope_id", event.ScopeID,
			"sequence", event.Sequence,
			"category", event.Category,
			"type", event.Type,
			"correlation_id", event.CorrelationID,
		)
	}

	return event, nil
}

func (b *Bus) Publish(ctx context.Context, category Category, eventType string, scopeID string, correlationID string, payload any) error {
	_, err := b.PublishEvent(ctx, PublishRequest{
		Category:      category,
		Type:          eventType,
		ScopeID:       scopeID,
		CorrelationID: correlationID,
		Payload:       payload,
	})
	return err
}

func cloneMetadata(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
