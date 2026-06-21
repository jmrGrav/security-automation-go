package poller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// LAPIDecision mirrors the JSON response from GET /v1/decisions.
type LAPIDecision struct {
	ID        int64  `json:"id"`
	Value     string `json:"value"`
	Type      string `json:"type"`
	Scenario  string `json:"scenario"`
	Duration  string `json:"duration"`
	Origin    string `json:"origin"`
	Scope     string `json:"scope"`
	Simulated bool   `json:"simulated"`
}

// LAPIAlert mirrors a single entry from `cscli alerts list -o json`.
type LAPIAlert struct {
	ID        int64        `json:"id"`
	Scenario  string       `json:"scenario"`
	Message   string       `json:"message"`
	CreatedAt string       `json:"created_at"`
	Source    alertSource  `json:"source"`
	Decisions []struct{}   `json:"decisions"`
	Events    []alertEvent `json:"events"`
}

type alertSource struct {
	IP       string `json:"ip"`
	Country  string `json:"cn"`
	ASNumber int64  `json:"as_number"`
	ASName   string `json:"as_name"`
	Range    string `json:"range"`
}

type alertEvent struct {
	Meta []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"meta"`
}

func (e *LAPIAlert) hasDecision() bool { return len(e.Decisions) > 0 }

// metaLookup returns the value for key from the first event's meta list.
func (e *LAPIAlert) metaLookup(key string) string {
	for _, ev := range e.Events {
		for _, m := range ev.Meta {
			if m.Key == key {
				return m.Value
			}
		}
	}
	return ""
}

// wafMatch holds the Coraza/OWASP-CRS rule detail for one matched event.
type wafMatch struct {
	RuleID       string
	Message      string
	Category     string
	URI          string
	MatchedZones string
	Data         string
	TargetFQDN   string
}

// primaryWAFMatch returns the rule-level detail of the event most likely to
// describe the actual attack, not CRS setup/bookkeeping rules. CRS emits one
// event per matched rule, and the first is often a body-inspection setup
// rule (e.g. native_rule:901340) with no matched payload. We prefer the
// first event carrying a non-empty "data" meta value (the matched payload),
// falling back to the first event with any rule_name if none match.
func (e *LAPIAlert) primaryWAFMatch() (wafMatch, bool) {
	var fallback wafMatch
	haveFallback := false
	for _, ev := range e.Events {
		m := metaOf(ev)
		ruleName := m["rule_name"]
		if ruleName == "" {
			continue
		}
		match := wafMatch{
			RuleID:       ruleName,
			Message:      m["message"],
			URI:          m["uri"],
			MatchedZones: m["matched_zones"],
			Data:         m["data"],
			TargetFQDN:   m["target_fqdn"],
		}
		match.Category = categorizeWAFRule(ruleName)
		if !haveFallback {
			fallback = match
			haveFallback = true
		}
		if match.Data != "" {
			return match, true
		}
	}
	return fallback, haveFallback
}

func metaOf(ev alertEvent) map[string]string {
	out := make(map[string]string, len(ev.Meta))
	for _, m := range ev.Meta {
		out[m.Key] = m.Value
	}
	return out
}

// categorizeWAFRule maps an OWASP CRS native_rule ID to a coarse attack
// category using the standard CRS rule-ID range convention.
func categorizeWAFRule(ruleName string) string {
	id := strings.TrimPrefix(ruleName, "native_rule:")
	switch {
	case strings.HasPrefix(id, "942"):
		return "sqli"
	case strings.HasPrefix(id, "94"):
		return "xss"
	case strings.HasPrefix(id, "932"), strings.HasPrefix(id, "933"):
		return "rce"
	case strings.HasPrefix(id, "930"):
		return "traversal"
	case strings.HasPrefix(id, "913"):
		return "scanner"
	case id != ruleName: // had the native_rule: prefix but no known range
		return "waf"
	default:
		return "waf"
	}
}

type lapiClient struct {
	url    string
	apiKey string
	http   *http.Client
}

func newLAPIClient(baseURL, apiKey string, timeout time.Duration) *lapiClient {
	return &lapiClient{
		url:    baseURL + "/v1/decisions?limit=100",
		apiKey: apiKey,
		http:   &http.Client{Timeout: timeout},
	}
}

func (c *lapiClient) fetchDecisions(ctx context.Context) ([]LAPIDecision, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("lapi: new request: %w", err)
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lapi: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("lapi: unexpected status %d: %s", resp.StatusCode, body)
	}

	var decisions []LAPIDecision
	if err := json.NewDecoder(resp.Body).Decode(&decisions); err != nil {
		return nil, fmt.Errorf("lapi: decode: %w", err)
	}
	return decisions, nil
}
