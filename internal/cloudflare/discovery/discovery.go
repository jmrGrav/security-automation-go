package discovery

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/cloudflare/pagination"
	"github.com/jm/security-automation-go/internal/cloudflare/transport"
)

type ResourceDiscovery interface {
	VerifyToken(ctx context.Context) (*models.TokenVerification, error)
	ListZones(ctx context.Context) ([]models.Zone, error)
	ListIPAccessRules(ctx context.Context, zoneID string) ([]models.IPAccessRule, error)
	ListFirewallLists(ctx context.Context, accountID string) ([]models.FirewallList, error)
	ListFirewallListItems(ctx context.Context, accountID, listID string) ([]models.FirewallListItem, error)
	ListWAFEventsSince(ctx context.Context, zoneID string, since, until time.Time, limit int) ([]models.WAFEvent, error)
}

type Client struct {
	transport *transport.Transport
}

func New(t *transport.Transport) *Client {
	return &Client{
		transport: t,
	}
}

func (c *Client) VerifyToken(ctx context.Context) (*models.TokenVerification, error) {
	const op = "cloudflare.discovery.VerifyToken"
	res, _, err := transport.ExecuteAndDecode[models.TokenVerification](ctx, c.transport, http.MethodGet, "/user/tokens/verify", nil, nil)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	return &res, nil
}

func (c *Client) ListZones(ctx context.Context) ([]models.Zone, error) {
	const op = "cloudflare.discovery.ListZones"
	fetch := func(ctx context.Context, page int) ([]models.Zone, *models.ResultInfo, error) {
		q := pagination.DefaultQuery(page, 50)
		return transport.ExecuteAndDecode[[]models.Zone](ctx, c.transport, http.MethodGet, "/zones", q, nil)
	}
	return pagination.TraverseAll(ctx, 50, fetch)
}

func (c *Client) ListIPAccessRules(ctx context.Context, zoneID string) ([]models.IPAccessRule, error) {
	const op = "cloudflare.discovery.ListIPAccessRules"

	fetch := func(ctx context.Context, page int) ([]models.IPAccessRule, *models.ResultInfo, error) {
		q := pagination.DefaultQuery(page, 100)
		path := fmt.Sprintf("/zones/%s/firewall/access_rules/rules", zoneID)
		return transport.ExecuteAndDecode[[]models.IPAccessRule](ctx, c.transport, http.MethodGet, path, q, nil)
	}

	return pagination.TraverseAll(ctx, 100, fetch)
}

func (c *Client) ListFirewallLists(ctx context.Context, accountID string) ([]models.FirewallList, error) {
	const op = "cloudflare.discovery.ListFirewallLists"

	fetch := func(ctx context.Context, page int) ([]models.FirewallList, *models.ResultInfo, error) {
		q := pagination.DefaultQuery(page, 50)
		path := fmt.Sprintf("/accounts/%s/rules/lists", accountID)
		return transport.ExecuteAndDecode[[]models.FirewallList](ctx, c.transport, http.MethodGet, path, q, nil)
	}

	return pagination.TraverseAll(ctx, 50, fetch)
}

func (c *Client) ListFirewallListItems(ctx context.Context, accountID, listID string) ([]models.FirewallListItem, error) {
	const op = "cloudflare.discovery.ListFirewallListItems"

	fetch := func(ctx context.Context, page int) ([]models.FirewallListItem, *models.ResultInfo, error) {
		q := pagination.DefaultQuery(page, 500)
		path := fmt.Sprintf("/accounts/%s/rules/lists/%s/items", accountID, listID)
		return transport.ExecuteAndDecode[[]models.FirewallListItem](ctx, c.transport, http.MethodGet, path, q, nil)
	}

	return pagination.TraverseAll(ctx, 500, fetch)
}

func (c *Client) ListWAFEventsSince(ctx context.Context, zoneID string, since, until time.Time, limit int) ([]models.WAFEvent, error) {
	const op = "cloudflare.discovery.ListWAFEventsSince"

	if limit <= 0 {
		limit = 50
	}
	if since.IsZero() {
		return nil, apperr.New(op, "since is required")
	}
	if until.IsZero() {
		until = time.Now().UTC()
	}

	type zoneData struct {
		FirewallEventsAdaptive []models.WAFEvent `json:"firewallEventsAdaptive"`
	}
	type viewerData struct {
		Zones []zoneData `json:"zones"`
	}
	type graphData struct {
		Viewer viewerData `json:"viewer"`
	}

	query := "query ListFirewallEvents($zoneTag: string, $filter: FirewallEventsAdaptiveFilter_InputObject, $limit: int) { viewer { zones(filter: { zoneTag: $zoneTag }) { firewallEventsAdaptive(filter: $filter, limit: $limit, orderBy: [datetime_DESC]) { action clientIP clientRequestPath clientRequestQuery host: clientRequestHTTPHost datetime source userAgent ruleId description } } } }"
	variables := map[string]any{
		"zoneTag": zoneID,
		"limit":   limit,
		"filter": map[string]any{
			"datetime_gt": since.UTC().Format(time.RFC3339),
			"datetime_lt": until.UTC().Format(time.RFC3339),
		},
	}

	data, err := transport.ExecuteGraphQL[graphData](ctx, c.transport, query, variables)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	if len(data.Viewer.Zones) == 0 {
		return []models.WAFEvent{}, nil
	}
	return data.Viewer.Zones[0].FirewallEventsAdaptive, nil
}
