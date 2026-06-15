package virustotal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/security/enrichment"
)

// LookupClient calls the VirusTotal v3 IP addresses endpoint and returns a
// ProviderVerdict. It is registered as a manual-mode LookupProvider — it only
// fires when ManualForensics is true (Forensic / Security Intelligence pages).
type LookupClient struct {
	client httpclient.Client
	apiKey string
}

func NewLookupClient(client httpclient.Client, apiKey string) *LookupClient {
	return &LookupClient{client: client, apiKey: apiKey}
}

func (c *LookupClient) Name() string { return "virustotal" }

func (c *LookupClient) Mode() enrichment.LookupMode { return enrichment.LookupModeManual }

func (c *LookupClient) Lookup(ctx context.Context, ip netip.Addr) (enrichment.ProviderVerdict, error) {
	if c.apiKey == "" {
		return enrichment.ProviderVerdict{}, fmt.Errorf("virustotal: api key not configured")
	}

	endpoint := quotaBaseURL + "/ip_addresses/" + url.PathEscape(ip.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return enrichment.ProviderVerdict{}, fmt.Errorf("virustotal: build request: %w", err)
	}
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(ctx, req)
	if err != nil {
		return enrichment.ProviderVerdict{}, fmt.Errorf("virustotal: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return enrichment.ProviderVerdict{}, fmt.Errorf("virustotal HTTP %d", resp.StatusCode)
	}

	var payload vtIPResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return enrichment.ProviderVerdict{}, fmt.Errorf("virustotal: decode: %w", err)
	}

	stats := payload.Data.Attributes.LastAnalysisStats
	malicious := stats.Malicious
	suspicious := stats.Suspicious
	reputation := payload.Data.Attributes.Reputation

	score := malicious
	note := fmt.Sprintf("malicious: %d, suspicious: %d, reputation: %d", malicious, suspicious, reputation)

	return enrichment.ProviderVerdict{
		Provider: "virustotal",
		Mode:     enrichment.LookupModeManual,
		Score:    score,
		Manual:   true,
		Note:     note,
	}, nil
}

type vtIPResponse struct {
	Data struct {
		Attributes struct {
			Reputation        int `json:"reputation"`
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}
