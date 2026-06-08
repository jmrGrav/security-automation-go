package poller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
