package router

import (
	"context"
	"testing"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/ai/providers"
	aiquota "github.com/jm/security-automation-go/internal/ai/quota"
)

type fakeProvider struct {
	name    providers.Name
	enabled bool
}

func (p fakeProvider) Name() providers.Name { return p.name }
func (p fakeProvider) Enabled() bool        { return p.enabled }
func (p fakeProvider) Explain(context.Context, ai.ExplainRequest) (ai.ExplainResponse, error) {
	return ai.ExplainResponse{Provider: string(p.name)}, nil
}
func (p fakeProvider) Quota(context.Context) aiquota.ProviderQuota {
	return aiquota.ProviderQuota{Provider: string(p.name), State: aiquota.Unknown}
}

func TestStaticSelectorPrefersHighestQuota(t *testing.T) {
	reg := aiquota.NewMemoryRegistry()
	reg.Set(aiquota.ProviderQuota{Provider: "openai", State: aiquota.Warning, TokensRemain: 20, RequestsRemain: 5})
	reg.Set(aiquota.ProviderQuota{Provider: "anthropic", State: aiquota.Normal, TokensRemain: 50, RequestsRemain: 20})
	sel := StaticSelector{
		Providers: []providers.Provider{
			fakeProvider{name: providers.OpenAI, enabled: true},
			fakeProvider{name: providers.Anthropic, enabled: true},
		},
		Quota: reg,
	}
	got, quota, err := sel.SelectProvider(context.Background(), ai.ExplainRequest{ProviderPreference: "auto"})
	if err != nil {
		t.Fatalf("SelectProvider returned error: %v", err)
	}
	if got == nil || got.Name() != providers.Anthropic {
		t.Fatalf("expected anthropic, got %#v", got)
	}
	if quota.State != aiquota.Normal {
		t.Fatalf("unexpected quota state: %v", quota.State)
	}
}

func TestStaticSelectorSkipsDisabledAndExhausted(t *testing.T) {
	reg := aiquota.NewMemoryRegistry()
	reg.Set(aiquota.ProviderQuota{Provider: "openai", State: aiquota.Disabled})
	reg.Set(aiquota.ProviderQuota{Provider: "anthropic", State: aiquota.Exhausted})
	sel := StaticSelector{
		Providers: []providers.Provider{
			fakeProvider{name: providers.OpenAI, enabled: false},
			fakeProvider{name: providers.Anthropic, enabled: true},
		},
		Quota: reg,
	}
	got, _, err := sel.SelectProvider(context.Background(), ai.ExplainRequest{ProviderPreference: "auto"})
	if err != nil {
		t.Fatalf("SelectProvider returned error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected no provider, got %#v", got)
	}
}

func TestStaticSelectorHonorsPreference(t *testing.T) {
	sel := StaticSelector{
		Providers: []providers.Provider{
			fakeProvider{name: providers.OpenAI, enabled: true},
			fakeProvider{name: providers.Gemini, enabled: true},
		},
		Quota: aiquota.NewMemoryRegistry(),
	}
	got, _, err := sel.SelectProvider(context.Background(), ai.ExplainRequest{ProviderPreference: "gemini"})
	if err != nil {
		t.Fatalf("SelectProvider returned error: %v", err)
	}
	if got == nil || got.Name() != providers.Gemini {
		t.Fatalf("expected gemini, got %#v", got)
	}
}

func TestStaticSelectorRoundRobinsAmongHealthyProviders(t *testing.T) {
	reg := aiquota.NewMemoryRegistry()
	reg.Set(aiquota.ProviderQuota{Provider: "openai", State: aiquota.Normal, TokensRemain: 50, RequestsRemain: 10, LastObservedAt: time.Now().UTC()})
	reg.Set(aiquota.ProviderQuota{Provider: "anthropic", State: aiquota.Normal, TokensRemain: 50, RequestsRemain: 10, LastObservedAt: time.Now().UTC()})
	sel := StaticSelector{
		Providers: []providers.Provider{
			fakeProvider{name: providers.OpenAI, enabled: true},
			fakeProvider{name: providers.Anthropic, enabled: true},
		},
		Quota: reg,
	}
	first, _, err := sel.SelectProvider(context.Background(), ai.ExplainRequest{ProviderPreference: "auto"})
	if err != nil {
		t.Fatalf("SelectProvider returned error: %v", err)
	}
	second, _, err := sel.SelectProvider(context.Background(), ai.ExplainRequest{ProviderPreference: "auto"})
	if err != nil {
		t.Fatalf("SelectProvider returned error: %v", err)
	}
	if first == nil || second == nil {
		t.Fatalf("expected providers to be selected, got %#v %#v", first, second)
	}
	if first.Name() == second.Name() {
		t.Fatalf("expected rotation across healthy providers, got %s twice", first.Name())
	}
}

func TestStaticSelectorRejectsUnavailablePreference(t *testing.T) {
	sel := StaticSelector{
		Providers: []providers.Provider{
			fakeProvider{name: providers.OpenAI, enabled: false},
			fakeProvider{name: providers.Gemini, enabled: true},
		},
		Quota: aiquota.NewMemoryRegistry(),
	}
	got, _, err := sel.SelectProvider(context.Background(), ai.ExplainRequest{ProviderPreference: "openai"})
	if err == nil {
		t.Fatalf("expected unavailable preference error, got provider %#v", got)
	}
	if got != nil {
		t.Fatalf("expected no provider, got %#v", got)
	}
}

func TestStaticSelectorReactivatesExpiredQuota(t *testing.T) {
	reg := aiquota.NewMemoryRegistry()
	past := time.Now().UTC().Add(-time.Minute)
	reg.Set(aiquota.ProviderQuota{
		Provider:   "openai",
		State:      aiquota.Exhausted,
		ResetAt:    &past,
		RetryAfter: ptrDuration(30 * time.Second),
	})
	sel := StaticSelector{
		Providers: []providers.Provider{
			fakeProvider{name: providers.OpenAI, enabled: true},
		},
		Quota: reg,
	}
	got, _, err := sel.SelectProvider(context.Background(), ai.ExplainRequest{ProviderPreference: "auto"})
	if err != nil {
		t.Fatalf("SelectProvider returned error: %v", err)
	}
	if got == nil || got.Name() != providers.OpenAI {
		t.Fatalf("expected expired quota to become eligible again, got %#v", got)
	}
}

func ptrDuration(d time.Duration) *time.Duration {
	return &d
}
