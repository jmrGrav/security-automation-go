package betterstack

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/httpclient"
)

type IngestClient interface {
	Send(ctx context.Context, event Event) error
}

type Client struct {
	httpClient httpclient.Client
	token      string
	endpoint   string
}

func NewClient(httpClient httpclient.Client, token string, ingestingHost string) *Client {
	return &Client{
		httpClient: httpClient,
		token:      token,
		endpoint:   normalizeEndpoint(ingestingHost),
	}
}

func (c *Client) Send(ctx context.Context, event Event) error {
	const op = "betterstack.Client.Send"

	if c == nil || c.httpClient == nil || strings.TrimSpace(c.token) == "" || strings.TrimSpace(c.endpoint) == "" {
		return nil
	}

	payload := make(map[string]any, len(event.Payload)+4)
	for k, v := range event.Payload {
		payload[k] = v
	}
	payload["message"] = event.Message
	payload["source"] = event.Source
	payload["level"] = event.Level
	if event.Timestamp.IsZero() {
		payload["dt"] = time.Now().UTC().Format(time.RFC3339)
	} else {
		payload["dt"] = event.Timestamp.UTC().Format(time.RFC3339)
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return apperr.Wrap(op, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(raw))
	if err != nil {
		return apperr.Wrap(op, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(ctx, req)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return apperr.Newf(op, "Better Stack HTTP %d", resp.StatusCode)
	}
	return nil
}

func normalizeEndpoint(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return strings.TrimRight(host, "/")
	}
	return "https://" + strings.TrimRight(host, "/")
}
