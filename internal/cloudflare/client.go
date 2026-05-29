package cloudflare

import (
	"context"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/client"
	"github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/snapshot"
)

// Legacy compatibility layer for initial scaffolding.
// New code should prefer internal/cloudflare/client.

type AccessRuleClient interface {
	DiscoverIPAccessRules(ctx context.Context, zoneID string, provenance snapshot.ProvenanceMetadata) (snapshot.Snapshot, error)
}

type ListClient interface {
	DiscoverFirewallLists(ctx context.Context, accountID string, provenance snapshot.ProvenanceMetadata) (snapshot.Snapshot, error)
	DiscoverFirewallListItems(ctx context.Context, accountID, listID string, provenance snapshot.ProvenanceMetadata) (snapshot.Snapshot, error)
}

type Client struct {
	inner *client.Client
}

func NewClient(httpClient httpclient.Client, token string) *Client {
	return &Client{
		inner: client.New(token, httpClient),
	}
}

func (c *Client) VerifyToken(ctx context.Context) (*models.TokenVerification, error) {
	return c.inner.Discovery.VerifyToken(ctx)
}

func (c *Client) ListZones(ctx context.Context) ([]models.Zone, error) {
	return c.inner.Discovery.ListZones(ctx)
}

func (c *Client) DiscoverIPAccessRules(ctx context.Context, zoneID string, provenance snapshot.ProvenanceMetadata) (snapshot.Snapshot, error) {
	rules, err := c.inner.Discovery.ListIPAccessRules(ctx, zoneID)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	objects := c.inner.Normalizer.IPAccessRules(rules)

	// For production discovery, we might want a way to build from objects directly or provide a dummy RawJSON.
	// Actually, the Builder currenty requires RawJSON for checksum integrity.
	// TODO: Add Object-based builder to internal/snapshot.

	return snapshot.Snapshot{
		Collection: snapshot.ResourceCollection{
			Objects: objects,
		},
	}, nil
}

func (c *Client) DiscoverFirewallLists(ctx context.Context, accountID string, provenance snapshot.ProvenanceMetadata) (snapshot.Snapshot, error) {
	lists, err := c.inner.Discovery.ListFirewallLists(ctx, accountID)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	objects := c.inner.Normalizer.FirewallLists(lists)
	return snapshot.Snapshot{
		Collection: snapshot.ResourceCollection{
			Objects: objects,
		},
	}, nil
}

func (c *Client) DiscoverFirewallListItems(ctx context.Context, accountID, listID string, provenance snapshot.ProvenanceMetadata) (snapshot.Snapshot, error) {
	items, err := c.inner.Discovery.ListFirewallListItems(ctx, accountID, listID)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	objects := c.inner.Normalizer.FirewallListItems(items)
	return snapshot.Snapshot{
		Collection: snapshot.ResourceCollection{
			Objects: objects,
		},
	}, nil
}

// TODO: Implement WAF GraphQL discovery
func (c *Client) ListWAFEventsSince(ctx context.Context, zoneID string, since time.Time) ([]models.WAFEvent, error) {
	return c.inner.ListWAFEventsSince(ctx, zoneID, since)
}
