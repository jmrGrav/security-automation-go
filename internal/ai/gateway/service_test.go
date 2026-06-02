package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/ai/providers"
	aiquota "github.com/jm/security-automation-go/internal/ai/quota"
	"github.com/jm/security-automation-go/internal/security/audit"
)

type testProvider struct {
	name        providers.Name
	enabled     bool
	explanation string
}

func (p testProvider) Name() providers.Name { return p.name }
func (p testProvider) Enabled() bool        { return p.enabled }
func (p testProvider) Explain(context.Context, ai.ExplainRequest) (ai.ExplainResponse, error) {
	explanation := p.explanation
	if explanation == "" {
		explanation = "ok"
	}
	return ai.ExplainResponse{Provider: string(p.name), Model: "test-model", Explanation: explanation}, nil
}
func (p testProvider) Quota(context.Context) aiquota.ProviderQuota {
	return aiquota.ProviderQuota{Provider: string(p.name), State: aiquota.Normal}
}

func TestServiceReturnsUnavailableWhenDisabled(t *testing.T) {
	svc := NewService(ai.Config{Enabled: false}, nil, nil, audit.AuditReader(nil))
	got, err := svc.Explain(context.Background(), ai.ExplainRequest{SubjectType: ai.SubjectProvider, SubjectID: "cloudflare"})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if got.Provider != "none" || got.QuotaState != string(aiquota.Unknown) {
		t.Fatalf("unexpected unavailable response: %+v", got)
	}
}

func TestServiceCachesUnavailableResponse(t *testing.T) {
	svc := NewService(ai.Config{Enabled: true}, nil, nil, nil)
	req := ai.ExplainRequest{SubjectType: ai.SubjectProvider, SubjectID: "cloudflare", ProviderPreference: "auto"}
	first, err := svc.Explain(context.Background(), req)
	if err != nil {
		t.Fatalf("first Explain returned error: %v", err)
	}
	second, err := svc.Explain(context.Background(), req)
	if err != nil {
		t.Fatalf("second Explain returned error: %v", err)
	}
	if !second.Cached {
		t.Fatalf("expected second response to be cached, got %+v", second)
	}
	if first.ContextHash != second.ContextHash {
		t.Fatalf("expected same context hash, got %q and %q", first.ContextHash, second.ContextHash)
	}
}

func TestServiceUsesProviderSelectionWhenAvailable(t *testing.T) {
	quotas := aiquota.NewMemoryRegistry()
	quotas.Set(aiquota.ProviderQuota{
		Provider:       "gemini",
		State:          aiquota.Normal,
		TokensRemain:   40,
		RequestsRemain: 20,
		LastObservedAt: time.Now().UTC(),
	})
	svc := NewService(ai.Config{Enabled: true}, []providers.Provider{
		testProvider{name: providers.Gemini, enabled: true},
	}, quotas, nil)
	got, err := svc.Explain(context.Background(), ai.ExplainRequest{
		SubjectType:        ai.SubjectProvider,
		SubjectID:          "provider-health",
		ProviderPreference: "auto",
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if got.Provider != string(providers.Gemini) {
		t.Fatalf("expected gemini provider selection, got %+v", got)
	}
	if got.QuotaState != string(aiquota.Normal) {
		t.Fatalf("unexpected quota state: %+v", got)
	}
}

func TestServiceUsesConfiguredProviderStrategyAndCappedLimits(t *testing.T) {
	quotas := aiquota.NewMemoryRegistry()
	quotas.Set(aiquota.ProviderQuota{
		Provider:       "openai",
		State:          aiquota.Normal,
		TokensRemain:   99,
		RequestsRemain: 99,
		LastObservedAt: time.Now().UTC(),
	})
	svc := NewService(ai.Config{
		Enabled:          true,
		ProviderStrategy: "openai",
		MaxContextBytes:  64,
		MaxOutputTokens:  32,
	}, []providers.Provider{
		testProvider{name: providers.OpenAI, enabled: true},
	}, quotas, nil)

	req := ai.ExplainRequest{
		SubjectType:        ai.SubjectProvider,
		SubjectID:          "provider-health",
		ProviderPreference: "",
		MaxContextBytes:    4096,
		MaxOutputTokens:    2048,
	}

	got, err := svc.Explain(context.Background(), req)
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if got.Provider != string(providers.OpenAI) {
		t.Fatalf("expected openai provider selection, got %+v", got)
	}

	effective := svc.normalizeRequest(req)
	if effective.MaxContextBytes != 64 || effective.MaxOutputTokens != 32 {
		t.Fatalf("expected capped limits, got %+v", effective)
	}

	key1 := cacheKey(effective, "ctxhash", hashString("provider-health"))
	key2 := cacheKey(ai.ExplainRequest{
		SubjectType:        ai.SubjectProvider,
		SubjectID:          "provider-health",
		ProviderPreference: "openai",
		MaxContextBytes:    64,
		MaxOutputTokens:    32,
	}, "ctxhash", hashString("provider-health"))
	if key1 != key2 {
		t.Fatalf("expected normalized cache key, got %q and %q", key1, key2)
	}
	if strings.Contains(key1, "provider-health") {
		t.Fatalf("cache key should not expose raw subject id: %s", key1)
	}
}

func TestServiceRedactsProviderResponseBeforeCaching(t *testing.T) {
	quotas := aiquota.NewMemoryRegistry()
	quotas.Set(aiquota.ProviderQuota{
		Provider:       "openai",
		State:          aiquota.Normal,
		TokensRemain:   10,
		RequestsRemain: 10,
		LastObservedAt: time.Now().UTC(),
	})
	svc := NewService(ai.Config{Enabled: true}, []providers.Provider{
		testProvider{name: providers.OpenAI, enabled: true, explanation: "echo Bearer secret-token api_key=secret-token"},
	}, quotas, nil)

	req := ai.ExplainRequest{
		SubjectType:        ai.SubjectProvider,
		SubjectID:          "Bearer secret-token",
		ProviderPreference: "openai",
	}
	got, err := svc.Explain(context.Background(), req)
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	for _, forbidden := range []string{"secret-token", "Bearer "} {
		if strings.Contains(got.Explanation, forbidden) {
			t.Fatalf("response leaked %q: %+v", forbidden, got)
		}
	}
	key := cacheKey(svc.normalizeRequest(req), got.ContextHash, hashString(svc.redactor.Redact(req.SubjectID).Text))
	if strings.Contains(key, "secret-token") {
		t.Fatalf("cache key leaked raw secret: %s", key)
	}
	entry, ok := svc.cache.Get(context.Background(), key)
	if !ok {
		t.Fatalf("expected cached entry for key %s", key)
	}
	for _, forbidden := range []string{"secret-token", "Bearer "} {
		if strings.Contains(entry.Explanation, forbidden) {
			t.Fatalf("cached explanation leaked %q: %+v", forbidden, entry)
		}
	}
}

type failingProvider struct {
	name     providers.Name
	enabled  bool
	failWith error
}

func (p failingProvider) Name() providers.Name { return p.name }
func (p failingProvider) Enabled() bool        { return p.enabled }
func (p failingProvider) Explain(context.Context, ai.ExplainRequest) (ai.ExplainResponse, error) {
	return ai.ExplainResponse{}, p.failWith
}
func (p failingProvider) Quota(context.Context) aiquota.ProviderQuota {
	return aiquota.ProviderQuota{Provider: string(p.name), State: aiquota.Unknown}
}

type disabledQuotaProvider struct {
	name    providers.Name
	enabled bool
}

func (p disabledQuotaProvider) Name() providers.Name { return p.name }
func (p disabledQuotaProvider) Enabled() bool        { return p.enabled }
func (p disabledQuotaProvider) Explain(context.Context, ai.ExplainRequest) (ai.ExplainResponse, error) {
	return ai.ExplainResponse{}, nil
}
func (p disabledQuotaProvider) Quota(context.Context) aiquota.ProviderQuota {
	return aiquota.ProviderQuota{Provider: string(p.name), State: aiquota.Disabled}
}

// ScenarioA: OpenAI unavailable, Anthropic selected
func TestScenarioA_OpenAIUnavailable_AnthropicSelected(t *testing.T) {
	quotas := aiquota.NewMemoryRegistry()
	quotas.Set(aiquota.ProviderQuota{Provider: "openai", State: aiquota.Unknown})
	quotas.Set(aiquota.ProviderQuota{Provider: "anthropic", State: aiquota.Normal, TokensRemain: 50, RequestsRemain: 20, LastObservedAt: time.Now().UTC()})

	svc := NewService(ai.Config{Enabled: true}, []providers.Provider{
		failingProvider{name: providers.OpenAI, enabled: true, failWith: errors.New("connection refused")},
		testProvider{name: providers.Anthropic, enabled: true},
		testProvider{name: providers.Gemini, enabled: true},
	}, quotas, nil)

	got, err := svc.Explain(context.Background(), ai.ExplainRequest{
		SubjectType:        ai.SubjectProvider,
		SubjectID:          "test",
		ProviderPreference: "auto",
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if got.Provider != string(providers.Anthropic) {
		t.Fatalf("Scenario A: expected anthropic fallback, got %q", got.Provider)
	}
	if strings.Contains(got.Explanation, "unavailable") {
		t.Fatalf("Scenario A: fallback should succeed, got explanation: %s", got.Explanation)
	}
	if got.QuotaState != string(aiquota.Normal) {
		t.Fatalf("Scenario A: unexpected quota state: %q", got.QuotaState)
	}
}

// ScenarioB: Anthropic unavailable, Gemini selected
func TestScenarioB_AnthropicUnavailable_GeminiSelected(t *testing.T) {
	quotas := aiquota.NewMemoryRegistry()
	quotas.Set(aiquota.ProviderQuota{Provider: "anthropic", State: aiquota.Unknown})
	quotas.Set(aiquota.ProviderQuota{Provider: "gemini", State: aiquota.Normal, TokensRemain: 40, RequestsRemain: 15, LastObservedAt: time.Now().UTC()})

	svc := NewService(ai.Config{Enabled: true}, []providers.Provider{
		testProvider{name: providers.OpenAI, enabled: true},
		failingProvider{name: providers.Anthropic, enabled: true, failWith: errors.New("api key invalid")},
		testProvider{name: providers.Gemini, enabled: true},
	}, quotas, nil)

	got, err := svc.Explain(context.Background(), ai.ExplainRequest{
		SubjectType:        ai.SubjectProvider,
		SubjectID:          "test",
		ProviderPreference: "auto",
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if got.Provider != string(providers.Gemini) && got.Provider != string(providers.OpenAI) {
		t.Fatalf("Scenario B: expected gemini or openai fallback, got %q", got.Provider)
	}
	if strings.Contains(got.Explanation, "unavailable") {
		t.Fatalf("Scenario B: fallback should succeed, got explanation: %s", got.Explanation)
	}
}

// ScenarioC: Rate-limited provider, others selected
func TestScenarioC_RateLimited_FallbackSelected(t *testing.T) {
	quotas := aiquota.NewMemoryRegistry()
	quotas.Set(aiquota.ProviderQuota{Provider: "openai", State: aiquota.Exhausted, TokensRemain: 0})
	quotas.Set(aiquota.ProviderQuota{Provider: "anthropic", State: aiquota.Normal, TokensRemain: 50, RequestsRemain: 20, LastObservedAt: time.Now().UTC()})

	svc := NewService(ai.Config{Enabled: true}, []providers.Provider{
		failingProvider{name: providers.OpenAI, enabled: true, failWith: errors.New("429 Too Many Requests")},
		testProvider{name: providers.Anthropic, enabled: true},
	}, quotas, nil)

	got, err := svc.Explain(context.Background(), ai.ExplainRequest{
		SubjectType:        ai.SubjectProvider,
		SubjectID:          "test",
		ProviderPreference: "auto",
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if got.Provider != string(providers.Anthropic) {
		t.Fatalf("Scenario C: expected anthropic fallback from rate limit, got %q", got.Provider)
	}
	if strings.Contains(got.Explanation, "unavailable") {
		t.Fatalf("Scenario C: fallback should succeed, got explanation: %s", got.Explanation)
	}
}

// ScenarioD: All disabled
func TestScenarioD_AllDisabled_UnavailableResponse(t *testing.T) {
	quotas := aiquota.NewMemoryRegistry()
	quotas.Set(aiquota.ProviderQuota{Provider: "openai", State: aiquota.Disabled})
	quotas.Set(aiquota.ProviderQuota{Provider: "anthropic", State: aiquota.Disabled})
	quotas.Set(aiquota.ProviderQuota{Provider: "gemini", State: aiquota.Disabled})

	svc := NewService(ai.Config{Enabled: true}, []providers.Provider{
		disabledQuotaProvider{name: providers.OpenAI, enabled: false},
		disabledQuotaProvider{name: providers.Anthropic, enabled: false},
		disabledQuotaProvider{name: providers.Gemini, enabled: false},
	}, quotas, nil)

	got, err := svc.Explain(context.Background(), ai.ExplainRequest{
		SubjectType:        ai.SubjectProvider,
		SubjectID:          "test",
		ProviderPreference: "auto",
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if got.Provider != "none" {
		t.Fatalf("Scenario D: expected provider 'none', got %q", got.Provider)
	}
	if !strings.Contains(strings.ToLower(got.Explanation), "unavailable") {
		t.Fatalf("Scenario D: expected unavailable message, got: %s", got.Explanation)
	}
	if got.QuotaState != string(aiquota.Unknown) {
		t.Fatalf("Scenario D: expected Unknown quota state, got %q", got.QuotaState)
	}
}

// Test: No panic/crash on provider errors
func TestFallbackNoPanic(t *testing.T) {
	quotas := aiquota.NewMemoryRegistry()
	quotas.Set(aiquota.ProviderQuota{Provider: "openai", State: aiquota.Unknown})
	quotas.Set(aiquota.ProviderQuota{Provider: "anthropic", State: aiquota.Normal, TokensRemain: 50, RequestsRemain: 20, LastObservedAt: time.Now().UTC()})

	svc := NewService(ai.Config{Enabled: true}, []providers.Provider{
		failingProvider{name: providers.OpenAI, enabled: true, failWith: errors.New("panic-inducing error")},
		testProvider{name: providers.Anthropic, enabled: true},
	}, quotas, nil)

	// Should not panic
	got, err := svc.Explain(context.Background(), ai.ExplainRequest{
		SubjectType:        ai.SubjectProvider,
		SubjectID:          "test",
		ProviderPreference: "auto",
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if got.Provider == "" {
		t.Fatalf("Fallback did not recover, got empty provider")
	}
}

// Test: No error leak in unavailable response
func TestFallbackNoErrorLeak(t *testing.T) {
	quotas := aiquota.NewMemoryRegistry()
	quotas.Set(aiquota.ProviderQuota{Provider: "openai", State: aiquota.Disabled})
	quotas.Set(aiquota.ProviderQuota{Provider: "anthropic", State: aiquota.Disabled})

	svc := NewService(ai.Config{Enabled: true}, []providers.Provider{
		failingProvider{name: providers.OpenAI, enabled: false, failWith: errors.New("secret connection string: postgres://user:password@db")},
		failingProvider{name: providers.Anthropic, enabled: false, failWith: errors.New("api_key=sk_test_ABC123XYZ leaked")},
	}, quotas, nil)

	got, err := svc.Explain(context.Background(), ai.ExplainRequest{
		SubjectType:        ai.SubjectProvider,
		SubjectID:          "test",
		ProviderPreference: "auto",
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	for _, secret := range []string{"password", "postgres", "sk_test_ABC123XYZ", "api_key"} {
		if strings.Contains(strings.ToLower(got.Explanation), strings.ToLower(secret)) {
			t.Fatalf("Error leak detected: %q in response: %s", secret, got.Explanation)
		}
	}
}

func TestFallbackNoSecretLeak(t *testing.T) {
	quotas := aiquota.NewMemoryRegistry()
	quotas.Set(aiquota.ProviderQuota{Provider: "openai", State: aiquota.Unknown})
	quotas.Set(aiquota.ProviderQuota{Provider: "anthropic", State: aiquota.Normal, TokensRemain: 50, RequestsRemain: 20, LastObservedAt: time.Now().UTC()})

	svc := NewService(ai.Config{Enabled: true}, []providers.Provider{
		failingProvider{name: providers.OpenAI, enabled: true, failWith: errors.New("bearer token invalid: Bearer test_api_key_value_abcxyz")},
		testProvider{name: providers.Anthropic, enabled: true},
	}, quotas, nil)

	got, err := svc.Explain(context.Background(), ai.ExplainRequest{
		SubjectType:        ai.SubjectProvider,
		SubjectID:          "test",
		ProviderPreference: "auto",
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	for _, secret := range []string{"test_api_key_value_abcxyz", "bearer", "token"} {
		if strings.Contains(strings.ToLower(got.Explanation), strings.ToLower(secret)) {
			t.Fatalf("Secret leak detected: %q in response: %s", secret, got.Explanation)
		}
	}
}
