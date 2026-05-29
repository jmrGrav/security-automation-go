package reportdedup

import (
	"context"
	"net/netip"
	"time"
)

// Store persists the last successful AbuseIPDB report per IP so the control
// plane can enforce a strict cross-source deduplication window.
type Store interface {
	LastReportedAt(ctx context.Context, ip netip.Addr) (time.Time, bool, error)
	MarkReported(ctx context.Context, ip netip.Addr, reportedAt time.Time, evidenceID string) error
}
