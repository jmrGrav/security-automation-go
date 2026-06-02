package gemini

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/ai/providers"
	aiquota "github.com/jm/security-automation-go/internal/ai/quota"
)

const defaultBaseURL = "https://generativelanguage.googleapis.com"

// Provider is a read-only Gemini API adapter.
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

// New constructs a disabled-by-default Gemini provider adapter.
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

func (p *Provider) Name() providers.Name { return providers.Gemini }

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
		return aiquota.ProviderQuota{Provider: string(providers.Gemini), State: aiquota.Unknown}
	}
	return p.lastQuota
}

func (p *Provider) Explain(ctx context.Context, req ai.ExplainRequest) (ai.ExplainResponse, error) {
	if p == nil || !p.Enabled() {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.Gemini, Reason: "provider disabled"}
	}

	callCtx := ctx
	var cancel context.CancelFunc
	if p.timeout > 0 {
		callCtx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}

	apiKey, err := providers.ReadAPIKeyFile(p.cfg.APIKeyFile)
	if err != nil {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.Gemini, Reason: "api key unavailable", Err: err}
	}

	maxTokens := req.MaxOutputTokens
	if maxTokens <= 0 {
		maxTokens = 1
	}
	payload := geminiRequest{
		Contents:         []geminiContent{{Parts: []geminiPart{{Text: providers.RedactPrompt(providers.PromptForRequest(req))}}}},
		GenerationConfig: &geminiGenerationConfig{MaxOutputTokens: maxTokens},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.Gemini, Reason: "marshal request", Err: err}
	}

	endpoint := strings.TrimRight(p.baseURL, "/") + "/v1beta/models/" + urlPathEscape(p.cfg.Model) + ":generateContent"
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.Gemini, Reason: "build request", Err: err}
	}
	httpReq.Header.Set("x-goog-api-key", apiKey)
	httpReq.Header.Set("content-type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		if callCtx.Err() != nil {
			return ai.ExplainResponse{}, &providers.Error{Provider: providers.Gemini, Reason: "request timeout", Retryable: true, Err: callCtx.Err()}
		}
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.Gemini, Reason: "request failed", Retryable: true, Err: err}
	}

	body, readErr := providers.ReadResponseBody(resp, 1<<20)
	if readErr != nil {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.Gemini, StatusCode: resp.StatusCode, Retryable: true, Reason: "read response body", Err: readErr}
	}

	if resp.StatusCode != http.StatusOK {
		p.observeQuota(aiquota.ObserveFailure(aiquota.ProviderQuota{Provider: string(p.Name()), State: aiquota.Unknown, Source: "status"}, resp.StatusCode, resp.Header, body))
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.Gemini, StatusCode: resp.StatusCode, Retryable: resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500, Reason: geminiFailureReason(resp.StatusCode), Err: errors.New("gemini request failed")}
	}

	q := aiquota.ObserveFailure(aiquota.ProviderQuota{Provider: string(p.Name()), State: aiquota.Normal, Source: "status"}, resp.StatusCode, resp.Header, body)
	p.observeQuota(q)

	text, model, inputTokens, outputTokens, totalTokens, err := parseGeminiResponse(body)
	if err != nil {
		return ai.ExplainResponse{}, &providers.Error{Provider: providers.Gemini, StatusCode: resp.StatusCode, Retryable: false, Reason: "parse response", Err: err}
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

func geminiFailureReason(status int) string {
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

type geminiRequest struct {
	Contents         []geminiContent         `json:"contents"`
	GenerationConfig *geminiGenerationConfig `json:"generationConfig,omitempty"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenerationConfig struct {
	MaxOutputTokens int `json:"maxOutputTokens,omitempty"`
}

type geminiResponse struct {
	Model      string `json:"model"`
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
		TotalTokenCount      int `json:"totalTokenCount"`
	} `json:"usageMetadata"`
}

func parseGeminiResponse(body []byte) (text string, model string, inputTokens int, outputTokens int, totalTokens int, err error) {
	var decoded geminiResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", "", 0, 0, 0, err
	}
	model = strings.TrimSpace(decoded.Model)
	for _, candidate := range decoded.Candidates {
		for _, part := range candidate.Content.Parts {
			if strings.TrimSpace(part.Text) != "" {
				text = strings.TrimSpace(part.Text)
				break
			}
		}
		if text != "" {
			break
		}
	}
	inputTokens = decoded.UsageMetadata.PromptTokenCount
	outputTokens = decoded.UsageMetadata.CandidatesTokenCount
	totalTokens = decoded.UsageMetadata.TotalTokenCount
	if text == "" {
		return "", model, inputTokens, outputTokens, totalTokens, errors.New("no candidate text in response")
	}
	return text, model, inputTokens, outputTokens, totalTokens, nil
}

func urlPathEscape(s string) string {
	return url.PathEscape(strings.TrimSpace(s))
}
