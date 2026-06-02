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

const quotaURL = "https://api.spamhaus.org/api/intel/v1/limits"

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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, quotaURL, nil)
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

	var payload siaLimitsResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		quota.RecordRefreshFailure("spamhaus")
		return quota.Observation{Provider: "spamhaus", QuotaSource: "api", State: quota.Unknown}, err
	}

	obs := buildSpamhausObservation(payload)
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

type siaLimitsResponse struct {
	Status int `json:"status"`
	Limits struct {
		QMS   int64 `json:"qms"`
		QMH   int64 `json:"qmh"`
		RLQPH int64 `json:"rl_qph"`
		RLQPM int64 `json:"rl_qpm"`
		RLQPS int64 `json:"rl_qps"`
	} `json:"limits"`
	Current struct {
		QPM   int64 `json:"qpm"`
		QPD   int64 `json:"qpd"`
		RLQPH int64 `json:"rl_qph"`
		RLQPM int64 `json:"rl_qpm"`
		RLQPS int64 `json:"rl_qps"`
	} `json:"current"`
}

func buildSpamhausObservation(payload siaLimitsResponse) quota.Observation {
	now := time.Now().UTC()
	obs := quota.Observation{
		Provider:    "spamhaus",
		Plan:        "limits",
		QuotaSource: "api:/api/intel/v1/limits",
		ObservedAt:  now,
	}

	type candidate struct {
		name      string
		allowed   int64
		used      int64
		remaining int64
		percent   float64
	}

	cands := []candidate{}
	if payload.Limits.QMH > 0 {
		remaining := payload.Limits.QMH - payload.Current.QPM
		if remaining < 0 {
			remaining = 0
		}
		cands = append(cands, candidate{name: "qmh", allowed: payload.Limits.QMH, used: payload.Current.QPM, remaining: remaining, percent: percentRemaining(payload.Limits.QMH, remaining)})
	}
	if payload.Limits.QMS > 0 {
		remaining := payload.Limits.QMS - payload.Current.QPM
		if remaining < 0 {
			remaining = 0
		}
		cands = append(cands, candidate{name: "qms", allowed: payload.Limits.QMS, used: payload.Current.QPM, remaining: remaining, percent: percentRemaining(payload.Limits.QMS, remaining)})
	}
	if payload.Limits.RLQPH > 0 {
		remaining := payload.Limits.RLQPH - payload.Current.RLQPH
		if remaining < 0 {
			remaining = 0
		}
		cands = append(cands, candidate{name: "rl_qph", allowed: payload.Limits.RLQPH, used: payload.Current.RLQPH, remaining: remaining, percent: percentRemaining(payload.Limits.RLQPH, remaining)})
	}
	if payload.Limits.RLQPM > 0 {
		remaining := payload.Limits.RLQPM - payload.Current.RLQPM
		if remaining < 0 {
			remaining = 0
		}
		cands = append(cands, candidate{name: "rl_qpm", allowed: payload.Limits.RLQPM, used: payload.Current.RLQPM, remaining: remaining, percent: percentRemaining(payload.Limits.RLQPM, remaining)})
	}
	if payload.Limits.RLQPS > 0 {
		remaining := payload.Limits.RLQPS - payload.Current.RLQPS
		if remaining < 0 {
			remaining = 0
		}
		cands = append(cands, candidate{name: "rl_qps", allowed: payload.Limits.RLQPS, used: payload.Current.RLQPS, remaining: remaining, percent: percentRemaining(payload.Limits.RLQPS, remaining)})
	}

	var best *candidate
	for i := range cands {
		cand := cands[i]
		if best == nil || cand.percent < best.percent {
			copyCand := cand
			best = &copyCand
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
	obs.Notes = []string{"official limits endpoint", "reset time not exposed by provider"}
	return quota.ClassifyObservation(obs)
}

func percentRemaining(limit, remaining int64) float64 {
	if limit <= 0 {
		return 0
	}
	return (float64(remaining) / float64(limit)) * 100
}
