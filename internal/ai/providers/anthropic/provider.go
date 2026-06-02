package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/ai/providers"
	aiquota "github.com/jm/security-automation-go/internal/ai/quota"
)

const defaultBaseURL = "https://api.anthropic.com"
const anthropicVersion = "2023-06-01"

// Provider is a read-only Anthropic Messages API adapter.
type Provider struct {
	cfg       ai.ProviderConfig
	baseURL   string
	client    *http.Client
	timeout   time.Duration
	lastQuota aiquota.ProviderQuota
	quotaSet  bool
}

// Option customizes the provider transport.
type Option func(*Provider)

// WithBaseURL overrides the default API base URL.
func WithBaseURL(baseURL string) Option {
	return func(p *Provider) {
		if strings.TrimSpace(baseURL) != "" {
			p.baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
		}
	}
}

// WithHTTPClient sets the HTTP client used for requests.
func WithHTTPClient(client *http.Client) Option {
	return func(p *Provider) {
		if client != nil {
			p.client = client
		}
	}
}

// WithTimeout sets the per-request timeout enforced by the adapter.
func WithTimeout(timeout time.Duration) Option {
	return func(p *Provider) {
		if timeout > 0 {
			p.timeout = timeout
		}
	}
}

// New constructs a disabled-by-default Anthropic provider adapter.
func New(cfg ai.ProviderConfig, opts ...Option) *Provider {
	p := &Provider{
		cfg:     cfg,
		baseURL: defaultBaseURL,
		client:  providers.DefaultHTTPClient(),
		timeout: 15 * time.Second,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}
	if p.client == nil {
		p.client = providers.DefaultHTTPClient()
	}
	if p.timeout <= 0 {
		p.timeout = 15 * time.Second
	}
	if strings.TrimSpace(p.baseURL) == "" {
		p.baseURL = defaultBaseURL
	}
	return p
}

func (p *Provider) Name() providers.Name { return providers.Anthropic }

func (p *Provider) Enabled() bool {
	if p == nil || !p.cfg.Enabled {
		return false
	}
	if strings.TrimSpace(p.cfg.Model) == "" || strings.TrimSpace(p.cfg.APIKeyFile) == "" {
		return false
	}
	if _, err := providers.ReadAPIKeyFile(p.cfg.APIKeyFile); err != nil {
		return false
	}
	return true
}

func (p *Provider) Quota(ctx context.Context) aiquota.ProviderQuota {
	_ = ctx
	if p == nil || !p.quotaSet {
		return aiquota.ProviderQuota{Provider: string(providers.Anthropic), State: aiquota.Unknown}
	}
	return p.lastQuota
}

func (p *Provider) Explain(ctx context.Context, req ai.ExplainRequest) (ai.ExplainResponse, error) {
	if p == nil || !p.Enabled() {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.Anthropic, Reason: "provider disabled"}
	}

	callCtx := ctx
	var cancel context.CancelFunc
	if p.timeout > 0 {
		callCtx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}

	apiKey, err := providers.ReadAPIKeyFile(p.cfg.APIKeyFile)
	if err != nil {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.Anthropic, Reason: "api key unavailable", Err: err}
	}

	maxTokens := req.MaxOutputTokens
	if maxTokens <= 0 {
		maxTokens = 1
	}
	payload := anthropicRequest{
		Model:       p.cfg.Model,
		MaxTokens:   maxTokens,
		System:      anthropicSystemPrompt(),
		Messages:    []anthropicMessage{{Role: "user", Content: []anthropicContent{{Type: "text", Text: providers.RedactPrompt(providers.PromptForRequest(req))}}}},
		Temperature: 0,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.Anthropic, Reason: "marshal request", Err: err}
	}

	endpoint := strings.TrimRight(p.baseURL, "/") + "/v1/messages"
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.Anthropic, Reason: "build request", Err: err}
	}
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("anthropic-version", anthropicVersion)
	httpReq.Header.Set("content-type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		if callCtx.Err() != nil {
			return ai.ExplainResponse{}, &providers.Error{Provider: providers.Anthropic, Reason: "request timeout", Retryable: true, Err: callCtx.Err()}
		}
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.Anthropic, Reason: "request failed", Retryable: true, Err: err}
	}

	body, readErr := providers.ReadResponseBody(resp, 1<<20)
	if readErr != nil {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.Anthropic, StatusCode: resp.StatusCode, Retryable: true, Reason: "read response body", Err: readErr}
	}

	q := aiquota.ParseAnthropicHeaders(resp.Header)
	if resp.StatusCode != http.StatusOK {
		p.observeQuota(aiquota.ObserveFailure(q, resp.StatusCode, resp.Header, body), true)
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.Anthropic, StatusCode: resp.StatusCode, Retryable: resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500, Reason: anthropicFailureReason(resp.StatusCode), Err: errors.New("anthropic request failed")}
	}
	p.observeQuota(q, false)

	text, model, inputTokens, outputTokens, totalTokens, err := parseAnthropicResponse(body)
	if err != nil {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.Anthropic, StatusCode: resp.StatusCode, Retryable: false, Reason: "parse response", Err: err}
	}
	if model == "" {
		model = p.cfg.Model
	}
	if totalTokens <= 0 {
		totalTokens = inputTokens + outputTokens
	}
	return ai.ExplainResponse{
		Provider:     string(p.Name()),
		Model:        model,
		Cached:       false,
		QuotaState:   string(p.Quota(ctx).State),
		Explanation:  text,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		TotalTokens:  totalTokens,
	}, nil
}

func (p *Provider) observeQuota(q aiquota.ProviderQuota, fromFailure bool) {
	if p == nil {
		return
	}
	if q.Provider == "" {
		q.Provider = string(p.Name())
	}
	if fromFailure && q.State == aiquota.Unknown {
		q.State = aiquota.Throttled
	}
	p.lastQuota = q
	p.quotaSet = true
}

func anthropicFailureReason(status int) string {
	switch status {
	case http.StatusTooManyRequests:
		return "rate limited"
	case http.StatusUnauthorized, http.StatusForbidden:
		return "unauthorized"
	case http.StatusBadRequest:
		return "invalid request"
	default:
		return fmt.Sprintf("status %d", status)
	}
}

func anthropicSystemPrompt() string {
	return "You are a read-only, explain-only assistant. Do not use tools or mutate anything."
}

type anthropicRequest struct {
	Model       string             `json:"model"`
	MaxTokens   int                `json:"max_tokens"`
	System      string             `json:"system"`
	Messages    []anthropicMessage `json:"messages"`
	Temperature float64            `json:"temperature,omitempty"`
}

type anthropicMessage struct {
	Role    string             `json:"role"`
	Content []anthropicContent `json:"content"`
}

type anthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicResponse struct {
	Model   string `json:"model"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func parseAnthropicResponse(body []byte) (text string, model string, inputTokens int, outputTokens int, totalTokens int, err error) {
	var decoded anthropicResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", "", 0, 0, 0, err
	}
	model = strings.TrimSpace(decoded.Model)
	for _, c := range decoded.Content {
		if strings.TrimSpace(c.Text) != "" {
			text = strings.TrimSpace(c.Text)
			break
		}
	}
	inputTokens = decoded.Usage.InputTokens
	outputTokens = decoded.Usage.OutputTokens
	totalTokens = inputTokens + outputTokens
	if text == "" {
		return "", model, inputTokens, outputTokens, totalTokens, errors.New("no content text in response")
	}
	return text, model, inputTokens, outputTokens, totalTokens, nil
}
