package openai

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/ai/providers"
	aiquota "github.com/jm/security-automation-go/internal/ai/quota"
)

func TestProviderExplainSuccessRedactsPromptAndParsesQuota(t *testing.T) {
	t.Parallel()

	var sawBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if got := r.URL.Path; got != "/v1/responses" {
			t.Fatalf("unexpected path: %s", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-openai-key" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		if got := r.Header.Get("Content-Type"); !strings.Contains(got, "application/json") {
			t.Fatalf("unexpected content-type: %q", got)
		}
		body, err := providers.ReadResponseBody(&http.Response{Body: r.Body}, 1<<20)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		sawBody = string(body)
		if strings.Contains(sawBody, "Bearer secret-token") {
			t.Fatalf("prompt was not redacted: %s", sawBody)
		}
		if strings.Contains(sawBody, "api_key=secret-token") {
			t.Fatalf("prompt was not redacted: %s", sawBody)
		}
		w.Header().Set("x-ratelimit-limit-requests", "60")
		w.Header().Set("x-ratelimit-remaining-requests", "59")
		w.Header().Set("x-ratelimit-limit-tokens", "100")
		w.Header().Set("x-ratelimit-remaining-tokens", "80")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":    "resp_123",
			"model": "gpt-test",
			"output": []any{
				map[string]any{
					"type": "message",
					"content": []any{
						map[string]any{"type": "output_text", "text": "openai ok"},
					},
				},
			},
		})
	}))
	defer srv.Close()

	provider := New(ai.ProviderConfig{Enabled: true, Model: "gpt-test", APIKey: "test-openai-key"}, WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithTimeout(250*time.Millisecond))

	got, err := provider.Explain(context.Background(), ai.ExplainRequest{
		SubjectType:        ai.SubjectProvider,
		SubjectID:          "api_key=secret-token",
		ProviderPreference: "auto",
		MaxOutputTokens:    12,
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if got.Provider != string(providers.OpenAI) || got.Model != "gpt-test" || got.Explanation != "openai ok" {
		t.Fatalf("unexpected response: %+v", got)
	}
	if got.QuotaState != string(aiquota.Normal) {
		t.Fatalf("unexpected quota state: %+v", got)
	}

	quota := provider.Quota(context.Background())
	if quota.State != aiquota.Normal || quota.RequestsRemain != 59 || quota.TokensRemain != 80 {
		t.Fatalf("unexpected quota observation: %+v", quota)
	}
	if sawBody == "" {
		t.Fatalf("expected request body to be captured")
	}
}

func TestProviderExplainParses429RetryAfter(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "2")
		w.Header().Set("x-ratelimit-limit-requests", "10")
		w.Header().Set("x-ratelimit-remaining-requests", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"quota exceeded"}}`))
	}))
	defer srv.Close()

	provider := New(ai.ProviderConfig{Enabled: true, Model: "gpt-test", APIKey: "test-openai-key"}, WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithTimeout(250*time.Millisecond))

	_, err := provider.Explain(context.Background(), ai.ExplainRequest{SubjectType: ai.SubjectProvider, SubjectID: "quota"})
	if err == nil {
		t.Fatal("expected error")
	}
	var perr *providers.Error
	if !errors.As(err, &perr) {
		t.Fatalf("expected providers.Error, got %T", err)
	}
	if !perr.Retryable || perr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("unexpected error classification: %+v", perr)
	}
	quota := provider.Quota(context.Background())
	if quota.State != aiquota.Exhausted || quota.RetryAfter == nil || *quota.RetryAfter != 2*time.Second {
		t.Fatalf("unexpected quota observation: %+v", quota)
	}
	if aiquota.CanUse(quota) {
		t.Fatalf("expected exhausted quota to be skipped: %+v", quota)
	}
}

func TestProviderExplainRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-ratelimit-limit-requests", "1")
		w.Header().Set("x-ratelimit-remaining-requests", "1")
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer srv.Close()

	provider := New(ai.ProviderConfig{Enabled: true, Model: "gpt-test", APIKey: "test-openai-key"}, WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithTimeout(250*time.Millisecond))

	_, err := provider.Explain(context.Background(), ai.ExplainRequest{SubjectType: ai.SubjectProvider, SubjectID: "bad-json"})
	if err == nil {
		t.Fatal("expected error")
	}
	var perr *providers.Error
	if !errors.As(err, &perr) {
		t.Fatalf("expected providers.Error, got %T", err)
	}
	if perr.Reason != "parse response" {
		t.Fatalf("unexpected error reason: %+v", perr)
	}
}

func TestProviderExplainTimesOut(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(75 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"model":"gpt-test","output":[{"type":"message","content":[{"type":"output_text","text":"late"}]}]}`))
	}))
	defer srv.Close()

	provider := New(ai.ProviderConfig{Enabled: true, Model: "gpt-test", APIKey: "test-openai-key"}, WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithTimeout(10*time.Millisecond))

	_, err := provider.Explain(context.Background(), ai.ExplainRequest{SubjectType: ai.SubjectProvider, SubjectID: "timeout"})
	if err == nil {
		t.Fatal("expected error")
	}
	var perr *providers.Error
	if !errors.As(err, &perr) {
		t.Fatalf("expected providers.Error, got %T", err)
	}
	if !perr.Retryable {
		t.Fatalf("expected timeout to be retryable: %+v", perr)
	}
}

func TestProviderExplainMissingOutputText(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"model":"gpt-test","output":[{"type":"message","content":[{"type":"output_text","text":""}]}]}`))
	}))
	defer srv.Close()

	provider := New(ai.ProviderConfig{Enabled: true, Model: "gpt-test", APIKey: "test-openai-key"}, WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithTimeout(250*time.Millisecond))

	_, err := provider.Explain(context.Background(), ai.ExplainRequest{SubjectType: ai.SubjectProvider, SubjectID: "missing-token"})
	if err == nil {
		t.Fatal("expected error")
	}
	var perr *providers.Error
	if !errors.As(err, &perr) {
		t.Fatalf("expected providers.Error, got %T", err)
	}
	if perr.Reason != "parse response" {
		t.Fatalf("unexpected error reason: %+v", perr)
	}
}
