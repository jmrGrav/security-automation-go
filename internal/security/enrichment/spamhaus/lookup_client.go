package spamhaus

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/security/enrichment"
)

const lookupBaseURL = "https://api.spamhaus.org/api/intel/v1"

// LookupClient queries the Spamhaus Intelligence API for a given IP's listing
// status. It is a manual-mode LookupProvider — it only fires on Forensic /
// Security Intelligence lookups (ManualForensics=true). An authentication
// failure (HTTP 401) is propagated as an error; the enrichment service is
// fail-open and will skip this provider without crashing.
type LookupClient struct {
	client httpclient.Client
	token  string
}

func NewLookupClient(client httpclient.Client, token string) *LookupClient {
	return &LookupClient{client: client, token: token}
}

func (c *LookupClient) Name() string { return "spamhaus" }

func (c *LookupClient) Mode() enrichment.LookupMode { return enrichment.LookupModeManual }

func (c *LookupClient) Lookup(ctx context.Context, ip netip.Addr) (enrichment.ProviderVerdict, error) {
	if c.token == "" {
		return enrichment.ProviderVerdict{}, fmt.Errorf("spamhaus: token not configured")
	}

	endpoint := lookupBaseURL + "/byobject/ip/" + url.PathEscape(ip.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return enrichment.ProviderVerdict{}, fmt.Errorf("spamhaus: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(ctx, req)
	if err != nil {
		return enrichment.ProviderVerdict{}, fmt.Errorf("spamhaus: request: %w", err)
	}
	defer resp.Body.Close()

	// 404 = IP not found in any dataset → clean
	if resp.StatusCode == http.StatusNotFound {
		return enrichment.ProviderVerdict{
			Provider: "spamhaus",
			Mode:     enrichment.LookupModeManual,
			Score:    0,
			Manual:   true,
			Note:     "not listed",
		}, nil
	}

	if resp.StatusCode >= 400 {
		return enrichment.ProviderVerdict{}, fmt.Errorf("spamhaus HTTP %d", resp.StatusCode)
	}

	var payload siaIPResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return enrichment.ProviderVerdict{}, fmt.Errorf("spamhaus: decode: %w", err)
	}

	// Build note from active listings
	var listed []string
	for _, r := range payload.Results {
		if r.Listed {
			listed = append(listed, r.Dataset)
		}
	}

	score := 0
	note := "not listed"
	if len(listed) > 0 {
		score = 1
		note = "listed: " + strings.Join(listed, ", ")
	}

	return enrichment.ProviderVerdict{
		Provider: "spamhaus",
		Mode:     enrichment.LookupModeManual,
		Score:    score,
		Manual:   true,
		Note:     note,
	}, nil
}

type siaIPResponse struct {
	Results []struct {
		Dataset string `json:"dataset"`
		Listed  bool   `json:"listed"`
	} `json:"results"`
}
