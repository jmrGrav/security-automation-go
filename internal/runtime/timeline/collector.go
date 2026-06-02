package timeline

import (
	"context"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/events"
)

type TimelineEntry struct {
	Timestamp     time.Time       `json:"timestamp"`
	Sequence      uint64          `json:"seq"`
	Category      events.Category `json:"category"`
	Type          string          `json:"type"`
	Actor         string          `json:"actor"`
	CorrelationID string          `json:"correlation_id"`
	Payload       any             `json:"payload,omitempty"`
	Metadata      map[string]any  `json:"metadata,omitempty"`
}

// Collector assembles a forensic timeline from journals and state history.
type Collector struct {
	store      events.EventStore
	maxEntries int
}

func NewCollector(store events.EventStore) *Collector {
	return NewCollectorWithLimit(store, 1000)
}

func NewCollectorWithLimit(store events.EventStore, maxEntries int) *Collector {
	if maxEntries <= 0 {
		maxEntries = 1000
	}
	return &Collector{store: store, maxEntries: maxEntries}
}

func (c *Collector) Assemble(ctx context.Context, scopeID string) ([]TimelineEntry, error) {
	evs, err := c.store.List(ctx, scopeID, 0)
	if err != nil {
		return nil, err
	}
	if c.maxEntries > 0 && len(evs) > c.maxEntries {
		evs = evs[len(evs)-c.maxEntries:]
	}

	entries := make([]TimelineEntry, len(evs))
	for i, ev := range evs {
		entries[i] = TimelineEntry{
			Timestamp:     ev.Timestamp,
			Sequence:      ev.Sequence,
			Category:      ev.Category,
			Type:          ev.Type,
			Actor:         ev.Actor,
			CorrelationID: ev.CorrelationID,
			Metadata:      ev.Metadata,
		}
		// Optional: parse payload based on type
	}

	return entries, nil
}
