package spamhaus

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/security/quota"
)

// submitCountURL is the Spamhaus Submit API health/count endpoint.
// The user's Spamhaus credential is a Submit API key (submit.spamhaus.org),
// not an Intelligence API key (api.spamhaus.org). The Submit API has no
// rate-limit quota endpoint; use submissions/count as a reachability probe.
const submitCountURL = "https://submit.spamhaus.org/portal/api/v1/submissions/count"

type QuotaClient struct {
	client   httpclient.Client
	token    string
	cacheTTL time.Duration

	mu        sync.Mutex
	cached    quota.Observation
	cachedAt  time.Time
	cachedSet bool
}

func NewQuotaClient(client httpclient.Client, token string) *QuotaClient {
	return &QuotaClient{
		client:   client,
		token:    token,
		cacheTTL: 30 * time.Minute,
	}
}

func (c *QuotaClient) Fetch(ctx context.Context) (quota.Observation, error) {
	if c == nil {
		return quota.Observation{Provider: "spamhaus", QuotaSource: "unavailable", State: quota.Unknown}, fmt.Errorf("quota client is nil")
	}
	if c.token == "" {
		quota.RecordRefreshFailure("spamhaus")
		return quota.Observation{Provider: "spamhaus", QuotaSource: "unavailable", State: quota.Unknown}, fmt.Errorf("spamhaus token is required")
	}
	if obs, ok := c.cachedObservation(); ok {
		return obs, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, submitCountURL, nil)
	if err != nil {
		quota.RecordRefreshFailure("spamhaus")
		return quota.Observation{Provider: "spamhaus", QuotaSource: "api", State: quota.Unknown}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(ctx, req)
	if err != nil {
		quota.RecordRefreshFailure("spamhaus")
		return quota.Observation{Provider: "spamhaus", QuotaSource: "api", State: quota.Unknown}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		quota.RecordRefreshFailure("spamhaus")
		return quota.Observation{Provider: "spamhaus", QuotaSource: "api", State: quota.Unknown}, fmt.Errorf("spamhaus HTTP %d", resp.StatusCode)
	}

	var payload submitCountResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		quota.RecordRefreshFailure("spamhaus")
		return quota.Observation{Provider: "spamhaus", QuotaSource: "api", State: quota.Unknown}, err
	}

	obs := buildSpamhausSubmitObservation(payload)
	c.store(obs)
	quota.DefaultRegistry().Record(obs)
	return obs, nil
}

func (c *QuotaClient) cachedObservation() (quota.Observation, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.cachedSet {
		return quota.Observation{}, false
	}
	if c.cacheTTL > 0 && time.Since(c.cachedAt) > c.cacheTTL {
		c.cachedSet = false
		return quota.Observation{}, false
	}
	return c.cached.Clone(), true
}

func (c *QuotaClient) store(obs quota.Observation) {
	c.mu.Lock()
	c.cached = obs.Clone()
	c.cachedAt = time.Now().UTC()
	c.cachedSet = true
	c.mu.Unlock()
}

// submitCountResponse is the response from the Spamhaus Submit API
// GET /portal/api/v1/submissions/count endpoint.
type submitCountResponse struct {
	Total    int `json:"total"`
	Approved int `json:"approved"`
	Pending  int `json:"pending"`
	Rejected int `json:"rejected"`
}

// buildSpamhausSubmitObservation converts a Submit API count response into a
// quota.Observation. The Submit API has no hard rate-limit; a 200 response
// means the credential is valid and the provider is reachable.
func buildSpamhausSubmitObservation(payload submitCountResponse) quota.Observation {
	obs := quota.Observation{
		Provider:    "spamhaus",
		Plan:        "submit",
		QuotaSource: "api:submit.spamhaus.org/portal/api/v1/submissions/count",
		ObservedAt:  time.Now().UTC(),
		UsedKnown:   true,
		Used:        float64(payload.Total),
		Notes:       []string{"submit api: no hard quota", fmt.Sprintf("submissions last 30d: total=%d approved=%d pending=%d rejected=%d", payload.Total, payload.Approved, payload.Pending, payload.Rejected)},
	}
	return quota.ClassifyObservation(obs)
}
