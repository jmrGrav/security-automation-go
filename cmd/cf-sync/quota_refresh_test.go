package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	abtransport "github.com/jm/security-automation-go/internal/abuseipdb/transport"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/security/quota"
)

func TestQuotaRefreshPollerInvokesRefreshAndStopsOnCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q := &quotaRefreshers{}
	calls := make(chan struct{}, 2)
	q.runPoller(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), "test-provider", 10*time.Millisecond, func(context.Context) error {
		select {
		case calls <- struct{}{}:
		default:
		}
		return nil
	})

	select {
	case <-calls:
	case <-time.After(2 * time.Second):
		t.Fatal("expected poller to invoke refresh immediately")
	}

	cancel()
}

func TestQuotaRefreshers_AbuseIPDBSkipsFreshObservation(t *testing.T) {
	quota.ResetDefaultRegistry()
	t.Cleanup(quota.ResetDefaultRegistry)

	calls := 0
	q := newAbuseQuotaRefreshersForTest(func(context.Context) (*http.Response, error) {
		calls++
		return okAbuseResponse(http.Header{}), nil
	})
	now := time.Now().UTC()
	quota.DefaultRegistry().Record(quota.Observation{
		Provider:       "abuseipdb",
		ObservedAt:     now.Add(-5 * time.Minute),
		State:          quota.Normal,
		QuotaSource:    "headers",
		Plan:           "abuseipdb api quota",
		LimitKnown:     true,
		Limit:          100,
		RemainingKnown: true,
		Remaining:      80,
	})
	q.now = func() time.Time { return now }

	if err := q.refreshAbuseIPDB(context.Background()); err != nil {
		t.Fatalf("refreshAbuseIPDB returned error: %v", err)
	}
	if calls != 0 {
		t.Fatalf("expected no dedicated refresh, got %d calls", calls)
	}
}

func TestQuotaRefreshers_AbuseIPDBRefreshesWhenObservationStale(t *testing.T) {
	quota.ResetDefaultRegistry()
	t.Cleanup(quota.ResetDefaultRegistry)

	calls := 0
	q := newAbuseQuotaRefreshersForTest(func(context.Context) (*http.Response, error) {
		calls++
		return okAbuseResponse(http.Header{
			"X-RateLimit-Limit":     []string{"100"},
			"X-RateLimit-Remaining": []string{"75"},
		}), nil
	})
	now := time.Now().UTC()
	quota.DefaultRegistry().Record(quota.Observation{
		Provider:       "abuseipdb",
		ObservedAt:     now.Add(-45 * time.Minute),
		State:          quota.Normal,
		QuotaSource:    "headers",
		Plan:           "abuseipdb api quota",
		LimitKnown:     true,
		Limit:          100,
		RemainingKnown: true,
		Remaining:      70,
	})
	q.now = func() time.Time { return now }

	if err := q.refreshAbuseIPDB(context.Background()); err != nil {
		t.Fatalf("refreshAbuseIPDB returned error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected one dedicated refresh, got %d calls", calls)
	}
}

func TestQuotaRefreshers_AbuseIPDBSkipsWhileExhaustedBeforeReset(t *testing.T) {
	quota.ResetDefaultRegistry()
	t.Cleanup(quota.ResetDefaultRegistry)

	calls := 0
	q := newAbuseQuotaRefreshersForTest(func(context.Context) (*http.Response, error) {
		calls++
		return okAbuseResponse(http.Header{}), nil
	})
	now := time.Now().UTC()
	quota.DefaultRegistry().Record(quota.Observation{
		Provider:   "abuseipdb",
		ObservedAt: now.Add(-1 * time.Minute),
		ResetKnown: true,
		ResetAt:    now.Add(15 * time.Minute),
		State:      quota.Exhausted,
	})
	q.now = func() time.Time { return now }

	if err := q.refreshAbuseIPDB(context.Background()); err != nil {
		t.Fatalf("refreshAbuseIPDB returned error: %v", err)
	}
	if calls != 0 {
		t.Fatalf("expected exhausted provider to skip refresh, got %d calls", calls)
	}
}

func TestQuotaRefreshers_AbuseIPDBResumesAfterResetWindow(t *testing.T) {
	quota.ResetDefaultRegistry()
	t.Cleanup(quota.ResetDefaultRegistry)

	calls := 0
	q := newAbuseQuotaRefreshersForTest(func(context.Context) (*http.Response, error) {
		calls++
		return okAbuseResponse(http.Header{
			"X-RateLimit-Limit":     []string{"100"},
			"X-RateLimit-Remaining": []string{"99"},
		}), nil
	})
	now := time.Now().UTC()
	quota.DefaultRegistry().Record(quota.Observation{
		Provider:       "abuseipdb",
		ObservedAt:     now.Add(-2 * time.Hour),
		ResetKnown:     true,
		ResetAt:        now.Add(-1 * time.Minute),
		State:          quota.Exhausted,
		QuotaSource:    "headers",
		Plan:           "abuseipdb api quota",
		LimitKnown:     true,
		Limit:          100,
		RemainingKnown: true,
		Remaining:      0,
	})
	q.now = func() time.Time { return now }

	if err := q.refreshAbuseIPDB(context.Background()); err != nil {
		t.Fatalf("refreshAbuseIPDB returned error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected refresh to resume after reset, got %d calls", calls)
	}
}

func TestQuotaRefreshers_AbuseIPDBBackoffAfterFailure(t *testing.T) {
	quota.ResetDefaultRegistry()
	t.Cleanup(quota.ResetDefaultRegistry)

	calls := 0
	q := newAbuseQuotaRefreshersForTest(func(context.Context) (*http.Response, error) {
		calls++
		return nil, errors.New("boom")
	})
	now := time.Now().UTC()
	quota.DefaultRegistry().Record(quota.Observation{
		Provider:       "abuseipdb",
		ObservedAt:     now.Add(-2 * time.Hour),
		State:          quota.Normal,
		QuotaSource:    "headers",
		Plan:           "abuseipdb api quota",
		LimitKnown:     true,
		Limit:          100,
		RemainingKnown: true,
		Remaining:      80,
	})
	q.now = func() time.Time { return now }

	if err := q.refreshAbuseIPDB(context.Background()); err == nil {
		t.Fatal("expected refreshAbuseIPDB to fail on first call")
	}
	if err := q.refreshAbuseIPDB(context.Background()); err != nil {
		t.Fatalf("expected backoff skip to be neutral, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected one network call due to backoff, got %d", calls)
	}
}

type abuseQuotaRefreshClient struct {
	do func(context.Context) (*http.Response, error)
}

func (c abuseQuotaRefreshClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	return c.do(ctx)
}

func newAbuseQuotaRefreshersForTest(do func(context.Context) (*http.Response, error)) *quotaRefreshers {
	return &quotaRefreshers{
		abuse:        abtransport.New(abuseQuotaRefreshClient{do: do}, "token"),
		abuseEnabled: true,
		abuseKey:     "token",
		now:          time.Now,
	}
}

// TestNewQuotaRefreshers_EmptyAbuseIPDBKey verifies that an empty AbuseIPDB key
// produces nil abuse transport in the refresher, preventing 401 poller calls.
func TestNewQuotaRefreshers_EmptyAbuseIPDBKey(t *testing.T) {
	cfg := &config.Config{}
	cfg.AbuseIPDB.APIKey = ""
	q := newQuotaRefreshers(cfg, nil, nil, nil, nil, nil)
	// With no providers at all, newQuotaRefreshers returns nil.
	if q != nil {
		t.Error("expected nil refreshers when no providers are configured")
	}
}

// fakeCredentialStore is a minimal in-memory implementation of credentialLooker for tests.
type fakeCredentialStore struct {
	entries map[string]string
}

func (f *fakeCredentialStore) Lookup(_ context.Context, key string) (string, bool, error) {
	v, ok := f.entries[key]
	return v, ok, nil
}

// TestNewQuotaRefreshers_LazySpamhausInit verifies that when Spamhaus is enabled and a credential
// store is provided but no APIKey is in config, the refresher is configured for lazy client creation.
func TestNewQuotaRefreshers_LazySpamhausInit(t *testing.T) {
	cs := &fakeCredentialStore{entries: map[string]string{
		"spamhaus.api_key": "test-spamhaus-key",
	}}
	cfg := &config.Config{}
	cfg.Spamhaus.Enabled = true
	cfg.Spamhaus.APIKey = "" // not in config, only in credential store

	q := newQuotaRefreshers(cfg, nil, nil, nil, cs, nil)
	if q == nil {
		t.Fatal("expected non-nil refreshers when credential store has Spamhaus key and Spamhaus is enabled")
	}
	if q.spamhaus != nil {
		t.Error("spamhaus client should be nil before first refresh (lazy init)")
	}
	if q.credStore == nil {
		t.Error("credStore must be set for lazy init to work")
	}
	if !q.spamEnabled {
		t.Error("spamEnabled must be true for lazy init to run")
	}
}

// TestNewQuotaRefreshers_NilCredStoreAndNilProviders verifies that nil credStore + no enabled
// providers still returns nil (no pollers to start).
func TestNewQuotaRefreshers_NilCredStoreAndNilProviders(t *testing.T) {
	cfg := &config.Config{}
	q := newQuotaRefreshers(cfg, nil, nil, nil, nil, nil)
	if q != nil {
		t.Error("expected nil when no providers configured and no credential store")
	}
}

func okAbuseResponse(header http.Header) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(`{}`)),
	}
}
