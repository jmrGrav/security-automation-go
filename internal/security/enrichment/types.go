package enrichment

import (
	"context"
	"net/netip"
	"time"

	"github.com/jm/security-automation-go/internal/security/enrichment/asn"
	"github.com/jm/security-automation-go/internal/security/enrichment/dns"
)

type LookupMode string

const (
	LookupModeAutomatic LookupMode = "automatic"
	LookupModeManual    LookupMode = "manual"
)

type Config struct {
	Enabled         bool
	DNSEnabled      bool
	ASNEnabled      bool
	Timeout         time.Duration
	CacheTTL        time.Duration
	TrustedSuffixes []string
}

type LookupOptions struct {
	ManualForensics bool
	SpamhausReport  bool
	// ReputationCheck triggers manual-mode lookup providers (AbuseIPDB,
	// VirusTotal, ...) from the automated reputation gate
	// (internal/security/reputation), independent of ManualForensics. This
	// lets the gate call Check/Lookup endpoints explicitly without weakening
	// the existing ManualForensics-only restriction used by the Forensic /
	// Security Intelligence UI pages. ManualForensics and ReputationCheck are
	// both "manual-mode" triggers but are kept as separate fields so the two
	// call sites can be reasoned about (and disabled) independently.
	ReputationCheck  bool
	LocalSignalScore int
}

type ProviderVerdict struct {
	Provider string
	Mode     LookupMode
	Score    int
	Manual   bool
	Note     string
}

type EnrichmentSummary struct {
	IP               netip.Addr
	DNS              dns.Result
	ASN              asn.Result
	Providers        []ProviderVerdict
	LocalSignalScore int
	CacheHit         bool
}

type Assessment struct {
	Score          int
	NoHardBan      bool
	HardBanAllowed bool
	Reasons        []string
}

type LookupProvider interface {
	Name() string
	Mode() LookupMode
	Lookup(ctx context.Context, ip netip.Addr) (ProviderVerdict, error)
}

type ReporterProvider interface {
	Name() string
	Report(ctx context.Context, ip netip.Addr, reason string) error
}

type DNSResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type ASNProvider interface {
	Name() string
	Lookup(ctx context.Context, ip netip.Addr) (asn.Result, error)
}
