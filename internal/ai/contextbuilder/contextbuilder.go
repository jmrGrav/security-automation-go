package contextbuilder

import (
	"context"
	"encoding/json"
	"fmt"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/security/audit"
)

// Context is the sanitized payload intended for future explain providers.
type Context struct {
	Hash    string
	Payload string
}

// Builder constructs a read-only, redacted context for a future AI request.
type Builder interface {
	Build(ctx context.Context, req ai.ExplainRequest) (Context, error)
}

// DefaultBuilder renders a JSON payload including relevant evidence.
type DefaultBuilder struct {
	Audit audit.AuditReader
}

type contextualAuditReader interface {
	EntriesContext(context.Context) ([]audit.AuditEntry, error)
}

// Build creates a compact context payload suitable for redaction and hashing.
func (b DefaultBuilder) Build(ctx context.Context, req ai.ExplainRequest) (Context, error) {
	if err := ctx.Err(); err != nil {
		return Context{}, err
	}
	var evidence []audit.AuditEntry
	if b.Audit != nil {
		all, err := readAuditEntries(ctx, b.Audit)
		if err != nil {
			return Context{}, err
		}
		// Filter by subject_id if it's an event or correlation
		for _, e := range all {
			if err := ctx.Err(); err != nil {
				return Context{}, err
			}
			if e.EventID == req.SubjectID || e.Correlation == req.SubjectID || e.Target == req.SubjectID {
				evidence = append(evidence, e)
			}
		}
		// If no specific match, just take last few for context
		if len(evidence) == 0 && len(all) > 0 {
			start := len(all) - 10
			if start < 0 {
				start = 0
			}
			evidence = all[start:]
		}
	}

	payload := struct {
		SubjectType        ai.SubjectType     `json:"subject_type"`
		SubjectID          string             `json:"subject_id"`
		ProviderPreference string             `json:"provider_preference"`
		Evidence           []audit.AuditEntry `json:"evidence,omitempty"`
	}{
		SubjectType:        req.SubjectType,
		SubjectID:          req.SubjectID,
		ProviderPreference: req.ProviderPreference,
		Evidence:           evidence,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Context{}, fmt.Errorf("build ai context: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Context{}, err
	}
	return Context{Payload: string(raw)}, nil
}

func readAuditEntries(ctx context.Context, reader audit.AuditReader) ([]audit.AuditEntry, error) {
	if contextual, ok := reader.(contextualAuditReader); ok {
		return contextual.EntriesContext(ctx)
	}
	return reader.Entries(), nil
}
