package client

import (
	"context"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/discovery"
	"github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/cloudflare/normalize"
	"github.com/jm/security-automation-go/internal/cloudflare/transport"
	"github.com/jm/security-automation-go/internal/httpclient"
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
