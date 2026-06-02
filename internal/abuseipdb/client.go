package abuseipdb

import (
	"context"
	"net/netip"

	"github.com/jm/security-automation-go/internal/abuseipdb/executor"
	"github.com/jm/security-automation-go/internal/abuseipdb/translator"
	"github.com/jm/security-automation-go/internal/abuseipdb/transport"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/security/quota"
)

type Client struct {
	Translator *translator.Translator
	Executor   executor.Executor
	transport  *transport.Transport
}

func NewClient(token string, httpClient httpclient.Client) *Client {
	t := transport.New(httpClient, token)
	return &Client{
		Translator: translator.New(),
		Executor:   executor.New(t),
		transport:  t,
	}
}

// RefreshQuota performs a lightweight read-only check request so the transport
// can capture live rate-limit headers without mutating provider state.
func (c *Client) RefreshQuota(ctx context.Context) (quota.Observation, error) {
	if c == nil || c.transport == nil {
		quota.RecordRefreshFailure("abuseipdb")
		return quota.Observation{Provider: "abuseipdb", QuotaSource: "unavailable", State: quota.Unknown}, nil
	}
	// Use a stable public IP to keep the request read-only and predictable.
	if _, err := c.transport.Check(ctx, netip.MustParseAddr("1.1.1.1").String()); err != nil {
		quota.RecordRefreshFailure("abuseipdb")
		return quota.Observation{Provider: "abuseipdb", QuotaSource: "api:/check", State: quota.Unknown}, err
	}
	obs, ok := quota.DefaultRegistry().Get("abuseipdb")
	if !ok {
		return quota.Observation{Provider: "abuseipdb", QuotaSource: "api:/check", State: quota.Unknown}, nil
	}
	return obs, nil
}
