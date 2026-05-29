// Package sinks owns outer-layer telemetry delivery and metrics emission.
package sinks

import (
	"context"
	"sync"

	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
)

type Sink interface {
	Publish(ctx context.Context, event tmevents.SecurityEvent) error
}

type MultiSink struct {
	sinks []Sink
}

func NewMulti(sinks ...Sink) *MultiSink {
	filtered := make([]Sink, 0, len(sinks))
	for _, sink := range sinks {
		if sink != nil {
			filtered = append(filtered, sink)
		}
	}
	return &MultiSink{sinks: filtered}
}

func (s *MultiSink) Publish(ctx context.Context, event tmevents.SecurityEvent) error {
	for _, sink := range s.sinks {
		if err := sink.Publish(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

type NoopSink struct{}

func (NoopSink) Publish(context.Context, tmevents.SecurityEvent) error { return nil }

type RecorderSink struct {
	mu     sync.Mutex
	Events []tmevents.SecurityEvent
}

func (r *RecorderSink) Publish(_ context.Context, event tmevents.SecurityEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Events = append(r.Events, event)
	return nil
}
