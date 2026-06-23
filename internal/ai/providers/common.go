package providers

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
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

// PromptForRequest renders a human-readable security analysis prompt from the explain request.
// It includes the built evidence context (req.Context) so the AI receives actual forensic data.
func PromptForRequest(req ai.ExplainRequest) string {
	var sb strings.Builder
	sb.WriteString("# Security Analysis Request\n")
	sb.WriteString(fmt.Sprintf("Subject Type: %s\n", req.SubjectType))
	sb.WriteString(fmt.Sprintf("Subject: %s\n", strings.TrimSpace(req.SubjectID)))
	if strings.TrimSpace(req.Context) != "" {
		sb.WriteString("\n## Evidence Context\n")
		sb.WriteString(strings.TrimSpace(req.Context))
		sb.WriteString("\n")
	}
	sb.WriteString("\nPlease analyze the subject and evidence above. Provide: observed behavior, risk level, key indicators, and recommended action. Be concise.")
	return sb.String()
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
