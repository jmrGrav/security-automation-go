package gemini

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/ai/providers"
	aiquota "github.com/jm/security-automation-go/internal/ai/quota"
)

func TestProviderExplainSuccess(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if got := r.URL.Path; got != "/v1beta/models/gemini-test:generateContent" {
			t.Fatalf("unexpected path: %s", got)
		}
		if got := r.Header.Get("x-goog-api-key"); got != "test-gemini-key" {
			t.Fatalf("unexpected api key header: %q", got)
		}
		body, err := providers.ReadResponseBody(&http.Response{Body: r.Body}, 1<<20)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if strings.Contains(string(body), "api_key=secret-token") {
			t.Fatalf("prompt was not redacted: %s", string(body))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": "gemini-test",
			"candidates": []any{
				map[string]any{
					"content": map[string]any{
						"parts": []any{
							map[string]any{"text": "gemini ok"},
						},
					},
				},
			},
		})
	}))
	defer srv.Close()

	keyFile := writeSecretFile(t, "test-gemini-key")
	provider := New(ai.ProviderConfig{Enabled: true, Model: "gemini-test", APIKeyFile: keyFile}, WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithTimeout(250*time.Millisecond))

	got, err := provider.Explain(context.Background(), ai.ExplainRequest{
		SubjectType:        ai.SubjectProvider,
		SubjectID:          "api_key=secret-token",
		ProviderPreference: "auto",
		MaxOutputTokens:    16,
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if got.Provider != string(providers.Gemini) || got.Model != "gemini-test" || got.Explanation != "gemini ok" {
		t.Fatalf("unexpected response: %+v", got)
	}
	if got.QuotaState != string(aiquota.Normal) {
		t.Fatalf("unexpected quota state: %+v", got)
	}
}

func TestProviderExplain429SetsExhaustedAndSkipsFutureUse(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":429,"message":"Resource has been exhausted (e.g. check quota).","status":"RESOURCE_EXHAUSTED"}}`))
	}))
	defer srv.Close()

	keyFile := writeSecretFile(t, "test-gemini-key")
	provider := New(ai.ProviderConfig{Enabled: true, Model: "gemini-test", APIKeyFile: keyFile}, WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithTimeout(250*time.Millisecond))

	_, err := provider.Explain(context.Background(), ai.ExplainRequest{SubjectType: ai.SubjectProvider, SubjectID: "quota"})
	if err == nil {
		t.Fatal("expected error")
	}
	var perr *providers.Error
	if !errors.As(err, &perr) {
		t.Fatalf("expected providers.Error, got %T", err)
	}
	if !perr.Retryable {
		t.Fatalf("expected 429 to be retryable: %+v", perr)
	}
	quota := provider.Quota(context.Background())
	if quota.State != aiquota.Exhausted {
		t.Fatalf("expected exhausted quota, got %+v", quota)
	}
	if aiquota.CanUse(quota) {
		t.Fatalf("expected exhausted quota to be skipped: %+v", quota)
	}
}

func writeSecretFile(t *testing.T, secret string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "api-key.txt")
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	return path
}
