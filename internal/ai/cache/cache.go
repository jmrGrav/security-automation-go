package cache

import (
	"context"
	"time"
)

// Entry is a cached AI explanation response.
type Entry struct {
	Key          string
	Provider     string
	Model        string
	QuotaState   string
	Explanation  string
	InputTokens  int
	OutputTokens int
	TotalTokens  int
	AuditID      string
	ExpiresAt    time.Time
}

// Store is the read-only cache contract for future AI explanations.
type Store interface {
	Get(ctx context.Context, key string) (Entry, bool)
	Put(ctx context.Context, entry Entry) error
}
