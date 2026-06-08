package providers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/ai/providers"
	"github.com/jm/security-automation-go/internal/ai/providers/anthropic"
	"github.com/jm/security-automation-go/internal/ai/providers/gemini"
	"github.com/jm/security-automation-go/internal/ai/providers/openai"
	aiquota "github.com/jm/security-automation-go/internal/ai/quota"
)

func TestProvidersAreDisabledByDefaultAndSkipNetworkWhenSecretMissing(t *testing.T) {
	cases := []struct {
		name string
		new  func(ai.ProviderConfig, string, *httptest.Server) providerContract
	}{
		{
			name: "openai",
			new: func(cfg ai.ProviderConfig, baseURL string, srv *httptest.Server) providerContract {
				return openai.New(cfg, openai.WithBaseURL(baseURL), openai.WithHTTPClient(srv.Client()))
			},
		},
		{
			name: "anthropic",
			new: func(cfg ai.ProviderConfig, baseURL string, srv *httptest.Server) providerContract {
				return anthropic.New(cfg, anthropic.WithBaseURL(baseURL), anthropic.WithHTTPClient(srv.Client()))
			},
		},
		{
			name: "gemini",
			new: func(cfg ai.ProviderConfig, baseURL string, srv *httptest.Server) providerContract {
				return gemini.New(cfg, gemini.WithBaseURL(baseURL), gemini.WithHTTPClient(srv.Client()))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			disabled := tc.new(ai.ProviderConfig{Enabled: false, Model: "model", APIKey: "", APIKeyFile: "/tmp/legacy-secret-file"}, srv.URL, srv)
			if disabled.Enabled() {
				t.Fatalf("expected %s to remain disabled by default", tc.name)
			}
			if _, err := disabled.Explain(context.Background(), ai.ExplainRequest{SubjectType: ai.SubjectProvider, SubjectID: "cloudflare"}); err == nil {
				t.Fatalf("expected disabled %s to reject explain call", tc.name)
			}
			if got := hits.Load(); got != 0 {
				t.Fatalf("expected no network call when disabled, got %d hits", got)
			}

			missingSecret := tc.new(ai.ProviderConfig{Enabled: true, Model: "model", APIKey: "", APIKeyFile: "/tmp/legacy-secret-file"}, srv.URL, srv)
			if missingSecret.Enabled() {
				t.Fatalf("expected %s to remain disabled without secret file", tc.name)
			}
			if _, err := missingSecret.Explain(context.Background(), ai.ExplainRequest{SubjectType: ai.SubjectProvider, SubjectID: "cloudflare"}); err == nil {
				t.Fatalf("expected %s to reject explain without secret file", tc.name)
			}
			if got := hits.Load(); got != 0 {
				t.Fatalf("expected no network call when secret missing, got %d hits", got)
			}
		})
	}
}

type providerContract interface {
	Enabled() bool
	Explain(context.Context, ai.ExplainRequest) (ai.ExplainResponse, error)
	Quota(context.Context) aiquota.ProviderQuota
	Name() providers.Name
}
