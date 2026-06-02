package anthropic

import (
	"context"
	"encoding/json"
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
		if got := r.URL.Path; got != "/v1/messages" {
			t.Fatalf("unexpected path: %s", got)
		}
		if got := r.Header.Get("x-api-key"); got != "test-anthropic-key" {
			t.Fatalf("unexpected api key header: %q", got)
		}
		if got := r.Header.Get("anthropic-version"); got != anthropicVersion {
			t.Fatalf("unexpected version: %q", got)
		}
		body, err := providers.ReadResponseBody(&http.Response{Body: r.Body}, 1<<20)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if strings.Contains(string(body), "Bearer secret-token") {
			t.Fatalf("prompt was not redacted: %s", string(body))
		}
		w.Header().Set("anthropic-ratelimit-requests-limit", "20")
		w.Header().Set("anthropic-ratelimit-requests-remaining", "3")
		w.Header().Set("anthropic-ratelimit-tokens-limit", "100")
		w.Header().Set("anthropic-ratelimit-tokens-remaining", "80")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":    "msg_1",
			"model": "claude-test",
			"content": []any{
				map[string]any{"type": "text", "text": "anthropic ok"},
			},
		})
	}))
	defer srv.Close()

	keyFile := writeSecretFile(t, "test-anthropic-key")
	provider := New(ai.ProviderConfig{Enabled: true, Model: "claude-test", APIKeyFile: keyFile}, WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithTimeout(250*time.Millisecond))

	got, err := provider.Explain(context.Background(), ai.ExplainRequest{
		SubjectType:        ai.SubjectProvider,
		SubjectID:          "Bearer secret-token",
		ProviderPreference: "auto",
		MaxOutputTokens:    24,
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if got.Provider != string(providers.Anthropic) || got.Model != "claude-test" || got.Explanation != "anthropic ok" {
		t.Fatalf("unexpected response: %+v", got)
	}
	if got.QuotaState != string(aiquota.Warning) {
		t.Fatalf("unexpected quota state: %+v", got)
	}

	quota := provider.Quota(context.Background())
	if quota.State != aiquota.Warning || quota.RequestsRemain != 3 || quota.TokensRemain != 80 {
		t.Fatalf("unexpected quota observation: %+v", quota)
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
