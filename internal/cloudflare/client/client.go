package client

import (
	"context"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/discovery"
	"github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/cloudflare/normalize"
	"github.com/jm/security-automation-go/internal/cloudflare/transport"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/security/quota"
)

type Client struct {
	Discovery  discovery.ResourceDiscovery
	Normalizer *normalize.Normalizer
}

func New(token string, httpClient httpclient.Client) *Client {
	return NewWithTransport(token, httpClient, transport.New(httpClient, token))
}

// NewWithTransport creates a Client reusing an existing transport instance.
func NewWithTransport(_ string, _ httpclient.Client, t *transport.Transport) *Client {
	return &Client{
		Discovery:  discovery.New(t),
		Normalizer: normalize.New(),
	}
}

func (c *Client) ListWAFEventsSince(ctx context.Context, zoneID string, since time.Time) ([]models.WAFEvent, error) {
	return c.Discovery.ListWAFEventsSince(ctx, zoneID, since, time.Now().UTC(), 50)
}

// RefreshQuota performs a lightweight verification request so the transport can
// capture live quota headers without touching any mutation path.
func (c *Client) RefreshQuota(ctx context.Context) (quota.Observation, error) {
	if c == nil || c.Discovery == nil {
		quota.RecordRefreshFailure("cloudflare")
		return quota.Observation{Provider: "cloudflare", QuotaSource: "unavailable", State: quota.Unknown}, nil
	}
	if _, err := c.Discovery.VerifyToken(ctx); err != nil {
		quota.RecordRefreshFailure("cloudflare")
		return quota.Observation{Provider: "cloudflare", QuotaSource: "api:/user/tokens/verify", State: quota.Unknown}, err
	}
	obs, ok := quota.DefaultRegistry().Get("cloudflare")
	if !ok {
		return quota.Observation{Provider: "cloudflare", QuotaSource: "api:/user/tokens/verify", State: quota.Unknown}, nil
	}
	return obs, nil
}
