package spamhaus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/jm/security-automation-go/internal/httpclient"
)

const submitIPURL = "https://submit.spamhaus.org/portal/api/v1/submissions/add/ip"

// SubmitClient implements Client by sending IP submissions to the Spamhaus
// Threat Intel Community Submit API (submit.spamhaus.org). A nil token causes
// every call to return nil (disabled, no-op).
type SubmitClient struct {
	client httpclient.Client
	token  string
	url    string
}

func NewSubmitClient(client httpclient.Client, token string) *SubmitClient {
	return &SubmitClient{client: client, token: token, url: submitIPURL}
}

// NewSubmitClientWithURL creates a SubmitClient with a custom endpoint URL (for testing).
func NewSubmitClientWithURL(client httpclient.Client, token, url string) *SubmitClient {
	return &SubmitClient{client: client, token: token, url: url}
}

type submitIPRequest struct {
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
}

func (c *SubmitClient) Report(ctx context.Context, ip netip.Addr, reason string) error {
	if c == nil || c.token == "" {
		return nil
	}

	body, err := json.Marshal(submitIPRequest{
		Value: ip.String(),
		Note:  reason,
	})
	if err != nil {
		return fmt.Errorf("spamhaus submit: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("spamhaus submit: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("spamhaus submit: request: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("spamhaus submit: HTTP %d: authentication failed — check spamhaus.api_key", resp.StatusCode)
	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("spamhaus submit: HTTP 429: rate limited")
	case resp.StatusCode >= 500:
		return fmt.Errorf("spamhaus submit: HTTP %d: server error (retryable)", resp.StatusCode)
	case resp.StatusCode >= 400:
		return fmt.Errorf("spamhaus submit: HTTP %d", resp.StatusCode)
	}
	return nil
}
