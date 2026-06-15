// Package abuseipdb provides an enrichment LookupProvider backed by the
// AbuseIPDB Check IP API (/api/v2/check). It is registered as a manual-mode
// provider — it fires only when ManualForensics is true (Forensic /
// Security Intelligence pages). The enrichment service's 6-hour cache ensures
// the API is called at most once per IP per session, preventing quota exhaustion.
package abuseipdb

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/jm/security-automation-go/internal/abuseipdb/transport"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/security/enrichment"
)

// LookupClient implements enrichment.LookupProvider using AbuseIPDB /check.
type LookupClient struct {
	t *transport.Transport
}

// NewLookupClient constructs a LookupClient. Pass the same httpclient.Client
// used by the rest of the runtime to share connection pools.
func NewLookupClient(client httpclient.Client, apiKey string) *LookupClient {
	return &LookupClient{t: transport.New(client, apiKey)}
}

func (c *LookupClient) Name() string { return "abuseipdb" }

// Mode returns LookupModeManual: this provider only fires on explicit forensic
// lookups. The per-event reporting path must never trigger Check calls.
func (c *LookupClient) Mode() enrichment.LookupMode { return enrichment.LookupModeManual }

// Lookup calls AbuseIPDB /check and returns a verdict. On any error (network,
// timeout, 429, invalid key) it returns a zero-score verdict with the error
// propagated — the enrichment service handles fail-open.
func (c *LookupClient) Lookup(ctx context.Context, ip netip.Addr) (enrichment.ProviderVerdict, error) {
	resp, err := c.t.Check(ctx, ip.String())
	if err != nil {
		return enrichment.ProviderVerdict{}, fmt.Errorf("abuseipdb lookup: %w", err)
	}
	d := resp.Data
	note := fmt.Sprintf("confidence=%d reports=%d isp=%q usage=%q country=%s",
		d.AbuseConfidenceScore, d.TotalReports, d.ISP, d.UsageType, d.CountryCode)
	if d.Domain != "" {
		note += fmt.Sprintf(" domain=%s", d.Domain)
	}
	return enrichment.ProviderVerdict{
		Provider: "abuseipdb",
		Mode:     enrichment.LookupModeManual,
		Score:    d.AbuseConfidenceScore,
		Manual:   true,
		Note:     note,
	}, nil
}
