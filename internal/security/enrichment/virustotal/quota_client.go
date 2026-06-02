package virustotal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/security/quota"
)

const quotaBaseURL = "https://www.virustotal.com/api/v3"

type QuotaClient struct {
	client   httpclient.Client
	apiKey   string
	cacheTTL time.Duration

	mu        sync.Mutex
	cached    quota.Observation
	cachedAt  time.Time
	cachedSet bool
}

func NewQuotaClient(client httpclient.Client, apiKey string) *QuotaClient {
	return &QuotaClient{
		client:   client,
		apiKey:   apiKey,
		cacheTTL: 30 * time.Minute,
	}
}

func (c *QuotaClient) Fetch(ctx context.Context) (quota.Observation, error) {
	if c == nil {
		return quota.Observation{Provider: "virustotal", QuotaSource: "unavailable", State: quota.Unknown}, fmt.Errorf("quota client is nil")
	}
	if strings.TrimSpace(c.apiKey) == "" {
		quota.RecordRefreshFailure("virustotal")
		return quota.Observation{Provider: "virustotal", QuotaSource: "unavailable", State: quota.Unknown}, fmt.Errorf("virustotal api key is required")
	}
	if obs, ok := c.cachedObservation(); ok {
		return obs, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, quotaBaseURL+"/users/"+url.PathEscape(c.apiKey), nil)
	if err != nil {
		quota.RecordRefreshFailure("virustotal")
		return quota.Observation{Provider: "virustotal", QuotaSource: "api", State: quota.Unknown}, err
	}
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(ctx, req)
	if err != nil {
		quota.RecordRefreshFailure("virustotal")
		return quota.Observation{Provider: "virustotal", QuotaSource: "api", State: quota.Unknown}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		quota.RecordRefreshFailure("virustotal")
		return quota.Observation{Provider: "virustotal", QuotaSource: "api", State: quota.Unknown}, fmt.Errorf("virustotal HTTP %d", resp.StatusCode)
	}

	var payload vtUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		quota.RecordRefreshFailure("virustotal")
		return quota.Observation{Provider: "virustotal", QuotaSource: "api", State: quota.Unknown}, err
	}

	obs := buildVirusTotalObservation(payload)
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

type vtUserResponse struct {
	Data struct {
		Attributes struct {
			Quotas map[string]struct {
				Allowed int64 `json:"allowed"`
				Used    int64 `json:"used"`
			} `json:"quotas"`
		} `json:"attributes"`
		ID string `json:"id"`
	} `json:"data"`
}

func buildVirusTotalObservation(payload vtUserResponse) quota.Observation {
	now := time.Now().UTC()
	obs := quota.Observation{
		Provider:    "virustotal",
		Plan:        "api_requests_daily",
		QuotaSource: "api:/users/{id}",
		ObservedAt:  now,
	}

	type candidate struct {
		name      string
		allowed   int64
		used      int64
		remaining int64
		percent   float64
	}
	var best *candidate
	for name, q := range payload.Data.Attributes.Quotas {
		if !strings.HasPrefix(name, "api_requests_") {
			continue
		}
		remaining := q.Allowed - q.Used
		if remaining < 0 {
			remaining = 0
		}
		percent := 0.0
		if q.Allowed > 0 {
			percent = (float64(remaining) / float64(q.Allowed)) * 100
		}
		cand := candidate{name: name, allowed: q.Allowed, used: q.Used, remaining: remaining, percent: percent}
		if best == nil || cand.percent < best.percent {
			best = &cand
		}
	}

	if best == nil {
		return quota.ClassifyObservation(obs)
	}

	obs.Plan = best.name
	obs.LimitKnown = true
	obs.Limit = float64(best.allowed)
	obs.UsedKnown = true
	obs.Used = float64(best.used)
	obs.RemainingKnown = true
	obs.Remaining = float64(best.remaining)
	obs.PercentKnown = true
	obs.RemainingPercent = best.percent
	obs.ResetKnown = true
	obs.ResetAt = nextVirusTotalReset(best.name, now)
	obs.Notes = []string{"official user quota endpoint", "most restrictive api_requests quota selected"}
	return quota.ClassifyObservation(obs)
}

func nextVirusTotalReset(name string, now time.Time) time.Time {
	switch {
	case strings.Contains(name, "hour"):
		return now.Truncate(time.Hour).Add(time.Hour)
	case strings.Contains(name, "day"):
		y, m, d := now.UTC().Date()
		return time.Date(y, m, d+1, 0, 0, 0, 0, time.UTC)
	case strings.Contains(name, "month"):
		y, m, _ := now.UTC().Date()
		return time.Date(y, m+1, 1, 0, 0, 0, 0, time.UTC)
	default:
		return now.Add(30 * time.Minute)
	}
}
