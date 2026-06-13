package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	abtransport "github.com/jm/security-automation-go/internal/abuseipdb/transport"
	cfclient "github.com/jm/security-automation-go/internal/cloudflare/client"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/security/enrichment/spamhaus"
	"github.com/jm/security-automation-go/internal/security/enrichment/virustotal"
	"github.com/jm/security-automation-go/internal/security/quota"
)

const (
	cloudflareQuotaRefreshInterval = 15 * time.Minute
	abuseIPDBQuotaRefreshInterval  = 15 * time.Minute
	thirdPartyQuotaRefreshInterval = 30 * time.Minute
	abuseIPDBObservationFreshness  = 30 * time.Minute
	abuseIPDBFailureBackoffBase    = 15 * time.Minute
	abuseIPDBFailureBackoffMax     = 2 * time.Hour
)

// credentialLooker is a minimal interface for credential store reads used by the quota refreshers.
type credentialLooker interface {
	Lookup(ctx context.Context, key string) (string, bool, error)
}

type quotaRefreshers struct {
	cloudflare *cfclient.Client
	abuse      *abtransport.Transport
	virustotal *virustotal.QuotaClient
	spamhaus   *spamhaus.QuotaClient

	// credStore and hc allow lazy client creation after a credential is saved via UI
	// without requiring a daemon restart.
	credStore   credentialLooker
	hc          httpclient.Client
	spamEnabled bool
	vtEnabled   bool

	mu               sync.Mutex
	abuseFailures    int
	abuseNextAttempt time.Time
	now              func() time.Time
}

func newQuotaRefreshers(cfg *config.Config, hc httpclient.Client, cf *cfclient.Client, abuse *abtransport.Transport, cs credentialLooker) *quotaRefreshers {
	if cfg == nil {
		return nil
	}
	var vt *virustotal.QuotaClient
	if cfg.VirusTotal.Enabled && cfg.VirusTotal.APIKey != "" {
		vt = virustotal.NewQuotaClient(hc, cfg.VirusTotal.APIKey)
	}
	var sh *spamhaus.QuotaClient
	if cfg.Spamhaus.Enabled && cfg.Spamhaus.APIKey != "" {
		sh = spamhaus.NewQuotaClient(hc, cfg.Spamhaus.APIKey)
	}
	spamLazy := cs != nil && cfg.Spamhaus.Enabled && sh == nil
	vtLazy := cs != nil && cfg.VirusTotal.Enabled && vt == nil
	if cf == nil && abuse == nil && vt == nil && sh == nil && !spamLazy && !vtLazy {
		return nil
	}
	return &quotaRefreshers{
		cloudflare:  cf,
		abuse:       abuse,
		virustotal:  vt,
		spamhaus:    sh,
		credStore:   cs,
		hc:          hc,
		spamEnabled: cfg.Spamhaus.Enabled,
		vtEnabled:   cfg.VirusTotal.Enabled,
		now:         time.Now,
	}
}

func (q *quotaRefreshers) start(ctx context.Context, logger *slog.Logger) {
	if q == nil {
		return
	}
	if q.cloudflare != nil {
		q.runPoller(ctx, logger, "cloudflare", cloudflareQuotaRefreshInterval, q.refreshCloudflare)
	}
	if q.abuse != nil {
		q.runPoller(ctx, logger, "abuseipdb", abuseIPDBQuotaRefreshInterval, q.refreshAbuseIPDB)
	}
	if q.virustotal != nil || (q.credStore != nil && q.vtEnabled) {
		q.runPoller(ctx, logger, "virustotal", thirdPartyQuotaRefreshInterval, q.refreshVirusTotal)
	}
	if q.spamhaus != nil || (q.credStore != nil && q.spamEnabled) {
		q.runPoller(ctx, logger, "spamhaus", thirdPartyQuotaRefreshInterval, q.refreshSpamhaus)
	}
}

func (q *quotaRefreshers) runPoller(ctx context.Context, logger *slog.Logger, provider string, interval time.Duration, refresh func(context.Context) error) {
	if interval <= 0 || refresh == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	go func() {
		q.refreshOnce(ctx, logger, provider, refresh)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				q.refreshOnce(ctx, logger, provider, refresh)
			}
		}
	}()
}

func (q *quotaRefreshers) refreshOnce(parent context.Context, logger *slog.Logger, provider string, refresh func(context.Context) error) {
	if refresh == nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, quotaRefreshTimeout())
	defer cancel()
	if err := refresh(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Warn("quota refresh failed", "provider", provider, "error", err)
	}
}

func quotaRefreshTimeout() time.Duration {
	return 10 * time.Second
}

func (q *quotaRefreshers) refreshCloudflare(ctx context.Context) error {
	_, err := q.cloudflare.RefreshQuota(ctx)
	return err
}

func (q *quotaRefreshers) refreshAbuseIPDB(ctx context.Context) error {
	if q == nil || q.abuse == nil {
		return nil
	}
	now := q.nowTime()
	obs, ok := quota.DefaultRegistry().Get("abuseipdb")
	if ok && obs.State == quota.Exhausted {
		if obs.ResetKnown && !obs.ResetAt.IsZero() {
			resetAt := obs.ResetAt.UTC()
			if now.Before(resetAt) {
				q.markAbuseCooldown(resetAt)
				return nil
			}
		}
		q.resetAbuseBackoff()
		if !obs.ResetKnown || obs.ResetAt.IsZero() {
			q.markAbuseCooldown(now.Add(abuseIPDBObservationFreshness))
			return nil
		}
	}
	if !q.shouldRefreshAbuseIPDB(now, obs, ok) {
		return nil
	}
	_, err := q.abuse.Check(ctx, "1.1.1.1")
	if err != nil {
		q.recordAbuseFailure(now)
		return err
	}
	q.resetAbuseBackoff()
	return nil
}

func (q *quotaRefreshers) refreshVirusTotal(ctx context.Context) error {
	if q.virustotal == nil && q.credStore != nil && q.vtEnabled {
		if v, ok, _ := q.credStore.Lookup(ctx, "virustotal.api_key"); ok && v != "" {
			q.virustotal = virustotal.NewQuotaClient(q.hc, v)
		}
	}
	if q.virustotal == nil {
		return nil
	}
	_, err := q.virustotal.Fetch(ctx)
	return err
}

func (q *quotaRefreshers) refreshSpamhaus(ctx context.Context) error {
	if q.spamhaus == nil && q.credStore != nil && q.spamEnabled {
		if v, ok, _ := q.credStore.Lookup(ctx, "spamhaus.api_key"); ok && v != "" {
			q.spamhaus = spamhaus.NewQuotaClient(q.hc, v)
		}
	}
	if q.spamhaus == nil {
		return nil
	}
	_, err := q.spamhaus.Fetch(ctx)
	return err
}

func (q *quotaRefreshers) shouldRefreshAbuseIPDB(now time.Time, obs quota.Observation, ok bool) bool {
	if !ok || obs.ObservedAt.IsZero() {
		return !q.abuseBackoffActive(now)
	}
	if now.Sub(obs.ObservedAt) <= abuseIPDBObservationFreshness {
		q.resetAbuseBackoff()
		return false
	}
	return !q.abuseBackoffActive(now)
}

func (q *quotaRefreshers) abuseBackoffActive(now time.Time) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return !q.abuseNextAttempt.IsZero() && now.Before(q.abuseNextAttempt)
}

func (q *quotaRefreshers) markAbuseCooldown(until time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if until.After(q.abuseNextAttempt) {
		q.abuseNextAttempt = until
	}
}

func (q *quotaRefreshers) recordAbuseFailure(now time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.abuseFailures++
	delay := abuseIPDBFailureBackoffBase << (q.abuseFailures - 1)
	if delay > abuseIPDBFailureBackoffMax {
		delay = abuseIPDBFailureBackoffMax
	}
	q.abuseNextAttempt = now.Add(delay)
}

func (q *quotaRefreshers) resetAbuseBackoff() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.abuseFailures = 0
	q.abuseNextAttempt = time.Time{}
}

func (q *quotaRefreshers) nowTime() time.Time {
	if q != nil && q.now != nil {
		return q.now().UTC()
	}
	return time.Now().UTC()
}
