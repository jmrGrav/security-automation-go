package contextbuilder

import (
	"context"
	"errors"
	"testing"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/security/audit"
)

type contextAwareAuditReader struct {
	entries []audit.AuditEntry
	calls   int
}

func (r *contextAwareAuditReader) Entries() []audit.AuditEntry {
	panic("Entries should not be called when EntriesContext is available")
}

func (r *contextAwareAuditReader) EntriesContext(ctx context.Context) ([]audit.AuditEntry, error) {
	r.calls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]audit.AuditEntry(nil), r.entries...), nil
}

func TestDefaultBuilderUsesContextAwareReader(t *testing.T) {
	t.Parallel()

	reader := &contextAwareAuditReader{
		entries: []audit.AuditEntry{
			{EventID: "evt-1", Target: "203.0.113.10"},
			{EventID: "evt-2", Target: "203.0.113.11"},
		},
	}
	builder := DefaultBuilder{Audit: reader}

	ctx := context.Background()
	got, err := builder.Build(ctx, ai.ExplainRequest{SubjectType: ai.SubjectAuditEvent, SubjectID: "evt-1"})
	if err != nil {
		t.Fatalf("expected successful build, got %v", err)
	}
	if reader.calls != 1 {
		t.Fatalf("expected context-aware reader to be used once, got %d", reader.calls)
	}
	if got.Payload == "" {
		t.Fatal("expected payload to be populated")
	}
}

func TestDefaultBuilderHonorsContextCancellation(t *testing.T) {
	t.Parallel()

	reader := &contextAwareAuditReader{
		entries: []audit.AuditEntry{
			{EventID: "evt-1", Target: "203.0.113.10"},
		},
	}
	builder := DefaultBuilder{Audit: reader}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := builder.Build(ctx, ai.ExplainRequest{SubjectType: ai.SubjectAuditEvent, SubjectID: "evt-1"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if reader.calls != 0 {
		t.Fatalf("expected cancelled build to short-circuit before reading, got %d calls", reader.calls)
	}
}
