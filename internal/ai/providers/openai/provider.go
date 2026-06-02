package openai

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

const defaultBaseURL = "https://api.openai.com"

// Provider is a read-only OpenAI Responses API adapter.
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

// New constructs a disabled-by-default OpenAI provider adapter.
func New(cfg ai.ProviderConfig, opts ...Option) *Provider {
	p := &Provider{
		cfg:     cfg,
		baseURL: defaultBaseURL,
		client:  providers.DefaultHTTPClient(),
		timeout: providersDefaultTimeout(),
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
		p.timeout = providersDefaultTimeout()
	}
	if strings.TrimSpace(p.baseURL) == "" {
		p.baseURL = defaultBaseURL
	}
	return p
}

func providersDefaultTimeout() time.Duration {
	return 15 * time.Second
}

func (p *Provider) Name() providers.Name { return providers.OpenAI }

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
	if p == nil {
		return aiquota.ProviderQuota{Provider: string(providers.OpenAI), State: aiquota.Unknown}
	}
	quota, ok := p.lastQuota, p.quotaSet
	if !ok {
		return aiquota.ProviderQuota{Provider: string(providers.OpenAI), State: aiquota.Unknown}
	}
	_ = ctx
	return quota
}

func (p *Provider) Explain(ctx context.Context, req ai.ExplainRequest) (ai.ExplainResponse, error) {
	if p == nil || !p.Enabled() {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.OpenAI, Reason: "provider disabled"}
	}

	callCtx := ctx
	var cancel context.CancelFunc
	if p.timeout > 0 {
		callCtx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}

	apiKey, err := providers.ReadAPIKeyFile(p.cfg.APIKeyFile)
	if err != nil {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.OpenAI, Reason: "api key unavailable", Err: err}
	}

	maxTokens := req.MaxOutputTokens
	if maxTokens <= 0 {
		maxTokens = 1
	}
	payload := openAIRequest{
		Model:           p.cfg.Model,
		Input:           providers.RedactPrompt(providers.PromptForRequest(req)),
		MaxOutputTokens: maxTokens,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.OpenAI, Reason: "marshal request", Err: err}
	}

	endpoint := strings.TrimRight(p.baseURL, "/") + "/v1/responses"
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.OpenAI, Reason: "build request", Err: err}
	}
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		if callCtx.Err() != nil {
			return ai.ExplainResponse{}, &providers.Error{Provider: providers.OpenAI, Reason: "request timeout", Retryable: true, Err: callCtx.Err()}
		}
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.OpenAI, Reason: "request failed", Retryable: true, Err: err}
	}

	body, readErr := providers.ReadResponseBody(resp, 1<<20)
	if readErr != nil {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.OpenAI, StatusCode: resp.StatusCode, Retryable: true, Reason: "read response body", Err: readErr}
	}

	if resp.StatusCode != http.StatusOK {
		p.observeQuota(aiquota.ObserveFailure(aiquota.ParseOpenAIHeaders(resp.Header), resp.StatusCode, resp.Header, body))
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.OpenAI, StatusCode: resp.StatusCode, Retryable: resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500, Reason: openAIFailureReason(resp.StatusCode), Err: errors.New("openai request failed")}
	}

	q := aiquota.ParseOpenAIHeaders(resp.Header)
	p.observeQuota(q)

	text, model, inputTokens, outputTokens, totalTokens, err := parseOpenAIResponse(body)
	if err != nil {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.OpenAI, StatusCode: resp.StatusCode, Retryable: false, Reason: "parse response", Err: err}
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

func (p *Provider) observeQuota(q aiquota.ProviderQuota) {
	if p == nil {
		return
	}
	if q.Provider == "" {
		q.Provider = string(p.Name())
	}
	p.lastQuota = q
	p.quotaSet = true
}

func openAIFailureReason(status int) string {
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

type openAIRequest struct {
	Model           string `json:"model"`
	Input           string `json:"input"`
	MaxOutputTokens int    `json:"max_output_tokens,omitempty"`
}

type openAIResponse struct {
	Model  string `json:"model"`
	Output []struct {
		Type    string `json:"type"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"output"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
		TotalTokens  int `json:"total_tokens"`
	} `json:"usage"`
}

func parseOpenAIResponse(body []byte) (text string, model string, inputTokens int, outputTokens int, totalTokens int, err error) {
	var decoded openAIResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", "", 0, 0, 0, err
	}
	model = strings.TrimSpace(decoded.Model)
	for _, output := range decoded.Output {
		for _, content := range output.Content {
			if strings.TrimSpace(content.Text) != "" {
				text = strings.TrimSpace(content.Text)
				break
			}
		}
		if text != "" {
			break
		}
	}
	inputTokens = decoded.Usage.InputTokens
	outputTokens = decoded.Usage.OutputTokens
	totalTokens = decoded.Usage.TotalTokens
	if text == "" {
		return "", model, inputTokens, outputTokens, totalTokens, errors.New("no output text in response")
	}
	return text, model, inputTokens, outputTokens, totalTokens, nil
}
