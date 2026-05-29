package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/httpclient"
)

const (
	BaseURL = "https://api.abuseipdb.com/api/v2"
)

// Transport handles AbuseIPDB-specific HTTP details.
type Transport struct {
	client httpclient.Client
	apiKey string
}

func New(client httpclient.Client, apiKey string) *Transport {
	return &Transport{
		client: client,
		apiKey: apiKey,
	}
}

// Report sends a report to AbuseIPDB.
func (t *Transport) Report(ctx context.Context, report models.ReportRequest) (*models.ReportResponse, error) {
	const op = "abuseipdb.transport.Report"

	payload, err := json.Marshal(report)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, BaseURL+"/report", bytes.NewReader(payload))
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}

	req.Header.Set("Key", t.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(ctx, req)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}

	if resp.StatusCode >= 400 {
		return nil, apperr.Newf(op, "AbuseIPDB HTTP %d: %s", resp.StatusCode, string(body))
	}

	var out models.ReportResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, apperr.Wrap(op, err)
	}

	return &out, nil
}

// Check queries AbuseIPDB /check before a potential global ban propagation.
func (t *Transport) Check(ctx context.Context, ip string) (*models.CheckResponse, error) {
	const op = "abuseipdb.transport.Check"

	u, err := url.Parse(BaseURL + "/check")
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	q := u.Query()
	q.Set("ipAddress", ip)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}

	req.Header.Set("Key", t.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := t.client.Do(ctx, req)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	if resp.StatusCode >= 400 {
		return nil, apperr.Newf(op, "AbuseIPDB HTTP %d: %s", resp.StatusCode, string(body))
	}

	var out models.CheckResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, apperr.Wrap(op, err)
	}
	return &out, nil
}
