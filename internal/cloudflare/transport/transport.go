package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/cloudflare/decode"
	"github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/logging"
	"github.com/jm/security-automation-go/internal/security/quota"
)

const (
	BaseURL = "https://api.cloudflare.com/client/v4"
)

// Transport handles Cloudflare-specific HTTP details.
type Transport struct {
	client httpclient.Client
	token  string
}

func New(client httpclient.Client, token string) *Transport {
	return &Transport{
		client: client,
		token:  token,
	}
}

// Request executes a Cloudflare API request with optional ETag support.
func (t *Transport) Request(ctx context.Context, method, path string, query url.Values, body io.Reader, etag string) ([]byte, string, error) {
	const op = "cloudflare.transport.Request"
	if isMutationMethod(method) {
		if state, ok := quota.DefaultRegistry().State("cloudflare"); ok && state == quota.Exhausted {
			return nil, "", apperr.Newf(op, "cloudflare quota exhausted; mutation suspended")
		}
	}

	fullURL := fmt.Sprintf("%s%s", BaseURL, path)
	if len(query) > 0 {
		fullURL += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, "", apperr.Wrap(op, err)
	}

	req.Header.Set("Authorization", "Bearer "+t.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if etag != "" {
		req.Header.Set("If-Match", etag)
	}

	resp, err := t.client.Do(ctx, req)
	if err != nil {
		return nil, "", apperr.Wrap(op, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", apperr.Wrap(op, err)
	}

	respETag := resp.Header.Get("ETag")
	obs := quota.ParseCloudflareHeaders(resp.Header)
	quota.DefaultRegistry().Record(obs)

	// Logging for debug only
	logger := logging.FromContext(ctx, nil)
	if logger != nil {
		logger.DebugContext(ctx, "Cloudflare API response",
			"status", resp.StatusCode,
			"method", method,
			"path", path,
			"etag", respETag,
			"quota_provider", obs.Provider,
			"quota_source", obs.QuotaSource,
			"quota_known", obs.LimitKnown || obs.RemainingKnown || obs.UsedKnown || obs.ResetKnown || len(obs.Notes) > 0,
			"quota_state", obs.State,
		)
	}

	// 1. Check for basic HTTP errors (other than 429 which might be retried)
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusTooManyRequests {
		return nil, "", apperr.Newf(op, "HTTP %d: %s", resp.StatusCode, string(raw))
	}

	return raw, respETag, nil
}

// ResponseEnvelope is a generic version of the Cloudflare envelope for strict decoding.
type ResponseEnvelope[T any] struct {
	Result     T                      `json:"result"`
	Success    bool                   `json:"success"`
	Errors     []models.ResponseError `json:"errors"`
	Messages   json.RawMessage        `json:"messages,omitempty"`
	ResultInfo *models.ResultInfo     `json:"result_info,omitempty"`
}

// ExecuteAndDecode is a helper that performs the request and decodes the envelope.
func ExecuteAndDecode[T any](ctx context.Context, t *Transport, method, path string, query url.Values, body io.Reader) (T, *models.ResultInfo, error) {
	const op = "cloudflare.transport.ExecuteAndDecode"
	var out T

	raw, _, err := t.Request(ctx, method, path, query, body, "")
	if err != nil {
		return out, nil, apperr.Wrap(op, err)
	}

	var env ResponseEnvelope[T]
	if err := decode.DecodeStrict(raw, &env); err != nil {
		return out, nil, apperr.Wrap(op, err)
	}

	if !env.Success {
		return out, nil, apperr.Newf(op, "Cloudflare API error: %v", env.Errors)
	}

	return env.Result, env.ResultInfo, nil
}

type GraphQLError struct {
	Message string `json:"message"`
}

type GraphQLResponse[T any] struct {
	Data   T              `json:"data"`
	Errors []GraphQLError `json:"errors,omitempty"`
}

func ExecuteGraphQL[T any](ctx context.Context, t *Transport, query string, variables map[string]any) (T, error) {
	const op = "cloudflare.transport.ExecuteGraphQL"
	var out T

	payload := map[string]any{
		"query":     query,
		"variables": variables,
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return out, apperr.Wrap(op, err)
	}

	raw, _, err := t.Request(ctx, http.MethodPost, "/graphql", nil, bytes.NewReader(rawPayload), "")
	if err != nil {
		return out, apperr.Wrap(op, err)
	}

	var resp GraphQLResponse[T]
	if err := decode.DecodeStrict(raw, &resp); err != nil {
		return out, apperr.Wrap(op, err)
	}
	if len(resp.Errors) > 0 {
		return out, apperr.Newf(op, "Cloudflare GraphQL error: %s", resp.Errors[0].Message)
	}
	return resp.Data, nil
}

// MutateAndDecode is a specialized helper for mutation endpoints with ETag support.
func MutateAndDecode[T any](ctx context.Context, t *Transport, method, path string, body io.Reader, etag string) (T, string, error) {
	const op = "cloudflare.transport.MutateAndDecode"
	var out T

	raw, respETag, err := t.Request(ctx, method, path, nil, body, etag)
	if err != nil {
		return out, "", apperr.Wrap(op, err)
	}

	var env ResponseEnvelope[T]
	if err := decode.DecodeStrict(raw, &env); err != nil {
		return out, "", apperr.Wrap(op, err)
	}

	if !env.Success {
		return out, "", apperr.Newf(op, "Cloudflare mutation error: %v", env.Errors)
	}

	return env.Result, respETag, nil
}

// DecodeEnvelope decodes the outer Cloudflare envelope without strict result checking.
// This is useful when the result type is variable or we only care about ResultInfo.
func DecodeEnvelope(raw []byte, target any) error {
	const op = "cloudflare.transport.DecodeEnvelope"
	return decode.DecodeStrict(raw, target)
}

// RateLimitHook implements httpclient.RateLimitHook for Cloudflare.
type RateLimitHook struct{}

func (h *RateLimitHook) Before(ctx context.Context, req *http.Request) error {
	return nil
}

func (h *RateLimitHook) After(ctx context.Context, req *http.Request, resp *http.Response, err error) error {
	if resp != nil {
		quota.DefaultRegistry().Record(quota.ParseCloudflareHeaders(resp.Header))
	}
	return nil
}

// CloudflareRetryAfter extracts the Retry-After header.
func CloudflareRetryAfter(resp *http.Response) time.Duration {
	return quota.CloudflareRetryAfter(resp)
}

func isMutationMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}
