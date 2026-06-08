package providers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
	aiquota "github.com/jm/security-automation-go/internal/ai/quota"
	airedaction "github.com/jm/security-automation-go/internal/ai/redaction"
)

const defaultTimeout = 15 * time.Second

// ReadAPIKeyFile reads a legacy secret file after verifying that the file is owner-only.
// legacy import/test compatibility only — not runtime credential source.
func ReadAPIKeyFile(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("api key file is not configured")
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("read api key file: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("read api key file: %s is a directory", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("api key file must be 0600 or stricter")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read api key file: %w", err)
	}

	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", errors.New("api key file is empty")
	}
	return key, nil
}

// ReadAPIKey returns the configured API key.
// File-based credentials are intentionally not consulted at runtime anymore.
func ReadAPIKey(cfg ai.ProviderConfig) (string, error) {
	if key := strings.TrimSpace(cfg.APIKey); key != "" {
		return key, nil
	}
	return "", errors.New("api key is not configured")
}

// RedactPrompt removes obvious secrets from the outbound prompt text.
func RedactPrompt(prompt string) string {
	return airedaction.DefaultRedactor{}.Redact(strings.TrimSpace(prompt)).Text
}

// PromptForRequest renders a compact, read-only prompt from the explain request.
func PromptForRequest(req ai.ExplainRequest) string {
	payload := struct {
		SubjectType        ai.SubjectType `json:"subject_type"`
		SubjectID          string         `json:"subject_id"`
		ProviderPreference string         `json:"provider_preference"`
		ContextHash        string         `json:"context_hash,omitempty"`
		MaxContextBytes    int            `json:"max_context_bytes,omitempty"`
		MaxOutputTokens    int            `json:"max_output_tokens,omitempty"`
	}{
		SubjectType:        req.SubjectType,
		SubjectID:          req.SubjectID,
		ProviderPreference: req.ProviderPreference,
		ContextHash:        req.ContextHash,
		MaxContextBytes:    req.MaxContextBytes,
		MaxOutputTokens:    req.MaxOutputTokens,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf(`{"subject_type":%q,"subject_id":%q}`, req.SubjectType, req.SubjectID)
	}
	return string(raw)
}

// DefaultHTTPClient returns a client with a safe timeout for provider requests.
func DefaultHTTPClient() *http.Client {
	return &http.Client{Timeout: defaultTimeout}
}

// ReadResponseBody reads a bounded response body and closes it.
func ReadResponseBody(resp *http.Response, limit int64) ([]byte, error) {
	if resp == nil {
		return nil, errors.New("response is nil")
	}
	defer resp.Body.Close()
	if limit <= 0 {
		limit = 1 << 20
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

type quotaState struct {
	mu    sync.RWMutex
	quota aiquota.ProviderQuota
	ok    bool
}

func (s *quotaState) set(quota aiquota.ProviderQuota) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quota = quota
	s.ok = true
}

func (s *quotaState) get() (aiquota.ProviderQuota, bool) {
	if s == nil {
		return aiquota.ProviderQuota{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.quota, s.ok
}
