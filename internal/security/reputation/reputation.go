// Package reputation defines a provider-agnostic boundary for external
// reputation lookups used by security enforcement decisions.
package reputation

import (
	"context"
	"net/netip"
	"time"
)

type FailureMode string

const (
	FailureModeAllow    FailureMode = "allow"
	FailureModeSuppress FailureMode = "suppress"
)

type Result struct {
	IP        netip.Addr `json:"ip"`
	Provider  string     `json:"provider"`
	Score     int        `json:"score"`
	CheckedAt time.Time  `json:"checked_at"`
	CacheHit  bool       `json:"cache_hit"`
}

type Checker interface {
	Check(ctx context.Context, ip netip.Addr) (Result, error)
}
