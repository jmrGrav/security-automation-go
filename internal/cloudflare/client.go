package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/client"
	"github.com/jm/security-automation-go/internal/cloudflare/models"
	cftransport "github.com/jm/security-automation-go/internal/cloudflare/transport"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/security/quota"
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

// EnforcementClient extends AccessRuleClient with mutation methods used by the
// CrowdSec → Cloudflare enforcement loop (mirrors Python's sync_cloudflare()).
type EnforcementClient interface {
	AccessRuleClient
	// ListIPAccessRulesByTag returns {ip/cidr: ruleID} for rules matching the given notes tag.
	ListIPAccessRulesByTag(ctx context.Context, zoneID, tag string) (map[string]string, error)
	// ListIPAccessRulesByNotePrefix returns every access rule whose notes
	// field starts with prefix, along with its rule ID and configured
	// IP/CIDR value. Used by the autoban ban-lifecycle cleanup worker as a
	// fallback lookup when a tracked entry's RuleID is unknown.
	ListIPAccessRulesByNotePrefix(ctx context.Context, zoneID, prefix string) ([]models.IPAccessRule, error)
	// AddIPAccessRule creates a block rule. target is "ip" or "ip_range".
	AddIPAccessRule(ctx context.Context, zoneID, value, notes, target string) (string, error)
	// AddIPAccessRuleWithMode creates a rule with an explicit mode (e.g.
	// "whitelist" for the trusted-networks registry's Cloudflare spoke).
	AddIPAccessRuleWithMode(ctx context.Context, zoneID, value, notes, target, mode string) (string, error)
	// DeleteIPAccessRule removes a rule by its CF rule ID.
	DeleteIPAccessRule(ctx context.Context, zoneID, ruleID string) error
}

type Client struct {
	inner *client.Client
	t     *cftransport.Transport
}

func NewClient(httpClient httpclient.Client, token string) *Client {
	t := cftransport.New(httpClient, token)
	return &Client{
		inner: client.NewWithTransport(token, httpClient, t),
		t:     t,
	}
}

func (c *Client) VerifyToken(ctx context.Context) (*models.TokenVerification, error) {
	return c.inner.Discovery.VerifyToken(ctx)
}

// RefreshQuota performs a lightweight read-only request so the transport can
// observe live quota headers without invoking any mutation path.
func (c *Client) RefreshQuota(ctx context.Context) (quota.Observation, error) {
	_, err := c.VerifyToken(ctx)
	if err != nil {
		quota.RecordRefreshFailure("cloudflare")
		return quota.Observation{Provider: "cloudflare", QuotaSource: "api:/user/tokens/verify", State: quota.Unknown}, err
	}
	obs, ok := quota.DefaultRegistry().Get("cloudflare")
	if !ok {
		return quota.Observation{Provider: "cloudflare", QuotaSource: "api:/user/tokens/verify", State: quota.Unknown}, nil
	}
	return obs, nil
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

// ── EnforcementClient implementation ─────────────────────────────────────────

// ListIPAccessRulesByTag returns {normalizedIP: ruleID} for all access rules
// whose notes field exactly matches tag.
// Mirrors Python's _parse_cf_rules_by_tag() + get_cf_blocked_ips().
func (c *Client) ListIPAccessRulesByTag(ctx context.Context, zoneID, tag string) (map[string]string, error) {
	rules, err := c.inner.Discovery.ListIPAccessRules(ctx, zoneID)
	if err != nil {
		return nil, fmt.Errorf("cloudflare.Client.ListIPAccessRulesByTag: %w", err)
	}
	result := make(map[string]string)
	for _, r := range rules {
		if r.Notes != tag {
			continue
		}
		val := r.Configuration.Value
		if val == "" {
			continue
		}
		// Normalize plain IPs (Python uses str(ipaddress.ip_address(val))).
		if parsed := net.ParseIP(val); parsed != nil {
			val = parsed.String()
		}
		result[val] = r.ID
	}
	return result, nil
}

// ListIPAccessRulesByNotePrefix returns every access rule whose notes field
// starts with prefix. Used as a fallback identification mechanism by the
// autoban ban-lifecycle cleanup worker when a tracked entry's RuleID is
// empty (e.g. lost local state); the rule's note still carries the
// "cf-sync:autoban:<reason>:exp=<RFC3339>" tag written at ban creation time.
func (c *Client) ListIPAccessRulesByNotePrefix(ctx context.Context, zoneID, prefix string) ([]models.IPAccessRule, error) {
	rules, err := c.inner.Discovery.ListIPAccessRules(ctx, zoneID)
	if err != nil {
		return nil, fmt.Errorf("cloudflare.Client.ListIPAccessRulesByNotePrefix: %w", err)
	}
	var out []models.IPAccessRule
	for _, r := range rules {
		if strings.HasPrefix(r.Notes, prefix) {
			out = append(out, r)
		}
	}
	return out, nil
}

// addIPAccessRulePayload is the CF API body for creating an IP access rule.
type addIPAccessRulePayload struct {
	Mode          string                   `json:"mode"`
	Configuration models.RuleConfiguration `json:"configuration"`
	Notes         string                   `json:"notes"`
}

// AddIPAccessRule creates a Cloudflare IP access rule (mode=block).
// target is "ip" or "ip_range". Returns the new rule ID.
// Mirrors Python's add_cf_rule().
func (c *Client) AddIPAccessRule(ctx context.Context, zoneID, value, notes, target string) (string, error) {
	return c.AddIPAccessRuleWithMode(ctx, zoneID, value, notes, target, "block")
}

// AddIPAccessRuleWithMode creates a Cloudflare IP access rule with an
// explicit mode ("block", "whitelist", "challenge", "js_challenge",
// "managed_challenge"). target is "ip" or "ip_range". Returns the new rule
// ID. Used by both the ban-lifecycle autoban path (mode=block) and the
// trusted-networks registry (mode=whitelist) — the two paths are kept
// distinguishable solely via note prefix (cf-sync:autoban: vs
// cf-sync:trusted:), never by mode alone, so cleanup/reconcile workers must
// always filter by their own note prefix before mutating anything.
func (c *Client) AddIPAccessRuleWithMode(ctx context.Context, zoneID, value, notes, target, mode string) (string, error) {
	payload := addIPAccessRulePayload{
		Mode:  mode,
		Notes: notes,
		Configuration: models.RuleConfiguration{
			Target: target,
			Value:  value,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("cloudflare.Client.AddIPAccessRuleWithMode: marshal: %w", err)
	}
	path := fmt.Sprintf("/zones/%s/firewall/access_rules/rules", zoneID)
	rule, _, err := cftransport.MutateAndDecode[models.IPAccessRule](
		ctx, c.t, http.MethodPost, path, bytes.NewReader(body), "",
	)
	if err != nil {
		return "", fmt.Errorf("cloudflare.Client.AddIPAccessRuleWithMode %s: %w", value, err)
	}
	return rule.ID, nil
}

// DeleteIPAccessRule removes a Cloudflare IP access rule by its rule ID.
// Mirrors Python's delete_cf_rule().
func (c *Client) DeleteIPAccessRule(ctx context.Context, zoneID, ruleID string) error {
	path := fmt.Sprintf("/zones/%s/firewall/access_rules/rules/%s", zoneID, ruleID)
	_, _, err := c.t.Request(ctx, http.MethodDelete, path, nil, nil, "")
	if err != nil {
		return fmt.Errorf("cloudflare.Client.DeleteIPAccessRule %s: %w", ruleID, err)
	}
	return nil
}
