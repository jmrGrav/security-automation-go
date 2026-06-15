package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
	aicache "github.com/jm/security-automation-go/internal/ai/cache"
	aicontext "github.com/jm/security-automation-go/internal/ai/contextbuilder"
	"github.com/jm/security-automation-go/internal/ai/providers"
	aiquota "github.com/jm/security-automation-go/internal/ai/quota"
	airedaction "github.com/jm/security-automation-go/internal/ai/redaction"
	airouter "github.com/jm/security-automation-go/internal/ai/router"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/security/audit"
)

// Service is the read-only explain gateway.
type Service struct {
	cfg       ai.Config
	cache     aicache.Store
	builder   aicontext.Builder
	redactor  airedaction.Redactor
	router    airouter.Selector
	providers []providers.Provider
	quotas    aiquota.Registry
	now       func() time.Time
}

// NewService constructs a fail-closed explain gateway.
func NewService(cfg ai.Config, providers []providers.Provider, quotas aiquota.Registry, auditReader audit.AuditReader, opts ...ServiceOption) *Service {
	if cfg.MaxContextBytes <= 0 {
		cfg.MaxContextBytes = 12_000
	}
	if cfg.MaxOutputTokens <= 0 {
		cfg.MaxOutputTokens = 800
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 15 * time.Minute
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.RateLimitPerMinute <= 0 {
		cfg.RateLimitPerMinute = 10
	}
	builder := aicontext.DefaultBuilder{Audit: auditReader}
	svc := &Service{
		cfg:       cfg,
		cache:     aicache.NewMemoryStore(),
		redactor:  airedaction.DefaultRedactor{},
		router:    airouter.StaticSelector{Providers: providers, Quota: quotas},
		providers: providers,
		quotas:    quotas,
		now:       time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&builder)
		}
	}
	svc.builder = builder
	return svc
}

// ServiceOption configures optional capabilities of the explain gateway.
type ServiceOption func(*aicontext.DefaultBuilder)

// WithEvidenceReader wires the evidence store into the context builder for IP subject enrichment.
func WithEvidenceReader(r aicontext.EvidenceReader) ServiceOption {
	return func(b *aicontext.DefaultBuilder) {
		if r != nil {
			b.Evidence = r
		}
	}
}

// WithIPEnricher wires the enrichment service into the context builder for IP subject enrichment.
func WithIPEnricher(e aicontext.IPEnricher) ServiceOption {
	return func(b *aicontext.DefaultBuilder) {
		if e != nil {
			b.Enricher = e
		}
	}
}

// Explain returns either a cached explanation or a clean unavailable response.
func (s *Service) Explain(ctx context.Context, req ai.ExplainRequest) (ai.ExplainResponse, error) {
	if err := ctx.Err(); err != nil {
		return ai.ExplainResponse{}, err
	}
	metrics.AIExplainRequestsTotal.Inc()
	effectiveReq := s.normalizeRequest(req)
	built, err := s.builder.Build(ctx, effectiveReq)
	if err != nil {
		metrics.AIExplainFailuresTotal.Inc()
		return ai.ExplainResponse{}, fmt.Errorf("build context: %w", err)
	}
	redacted := s.redactor.Redact(built.Payload)
	ctxHash := hashString(redacted.Text)
	effectiveReq.Context = redacted.Text
	subjectHash := hashString(s.redactor.Redact(effectiveReq.SubjectID).Text)
	cacheKey := cacheKey(effectiveReq, ctxHash, subjectHash)

	if !s.cfg.Enabled {
		resp := s.unavailableResponse("AI explain disabled")
		resp.ContextHash = ctxHash
		_ = s.cache.Put(ctx, aicache.Entry{
			Key:         cacheKey,
			Provider:    resp.Provider,
			Model:       resp.Model,
			QuotaState:  resp.QuotaState,
			Explanation: resp.Explanation,
			AuditID:     resp.AuditID,
			ExpiresAt:   s.now().Add(s.ttlForState(aiquota.Unknown)),
		})
		return resp, nil
	}

	if entry, ok := s.cache.Get(ctx, cacheKey); ok {
		metrics.AIExplainCacheHitsTotal.Inc()
		return ai.ExplainResponse{
			Provider:     entry.Provider,
			Model:        entry.Model,
			Cached:       true,
			QuotaState:   entry.QuotaState,
			Explanation:  entry.Explanation,
			InputTokens:  entry.InputTokens,
			OutputTokens: entry.OutputTokens,
			TotalTokens:  entry.TotalTokens,
			ContextHash:  ctxHash,
			AuditID:      entry.AuditID,
		}, nil
	}

	return s.explainWithFallback(ctx, effectiveReq, cacheKey, ctxHash)
}

func (s *Service) unavailableResponse(reason string) ai.ExplainResponse {
	return ai.ExplainResponse{
		Provider:    "none",
		Model:       "",
		Cached:      false,
		QuotaState:  string(aiquota.Unknown),
		Explanation: "AI explain unavailable: " + reason,
		AuditID:     "",
	}
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func cacheKey(req ai.ExplainRequest, contextHash, subjectHash string) string {
	keyMaterial := struct {
		ProviderPreference string `json:"provider_preference"`
		SubjectType        string `json:"subject_type"`
		SubjectIDHash      string `json:"subject_id_hash"`
		ContextHash        string `json:"context_hash"`
		MaxContextBytes    int    `json:"max_context_bytes"`
		MaxOutputTokens    int    `json:"max_output_tokens"`
	}{
		ProviderPreference: strings.ToLower(strings.TrimSpace(req.ProviderPreference)),
		SubjectType:        strings.ToLower(string(req.SubjectType)),
		SubjectIDHash:      subjectHash,
		ContextHash:        contextHash,
		MaxContextBytes:    req.MaxContextBytes,
		MaxOutputTokens:    req.MaxOutputTokens,
	}
	raw, err := json.Marshal(keyMaterial)
	if err != nil {
		return hashString(contextHash)
	}
	return hashString(string(raw))
}

func (s *Service) explainWithFallback(ctx context.Context, req ai.ExplainRequest, cacheKey, ctxHash string) (ai.ExplainResponse, error) {
	attempted := make(map[string]struct{}, len(s.providers))
	for attempts := 0; attempts < maxIntLocal(1, len(s.providers)); attempts++ {
		provider, _, err := s.router.SelectProvider(ctx, req)
		if err != nil || provider == nil {
			metrics.AIExplainFailuresTotal.Inc()
			resp := s.unavailableResponse("no AI provider is available")
			resp.ContextHash = ctxHash
			s.cacheUnavailable(ctx, cacheKey, resp, aiquota.Unknown)
			return resp, nil
		}
		providerName := string(provider.Name())
		if _, ok := attempted[providerName]; ok {
			metrics.AIProviderSkippedTotal.WithLabelValues(providerName).Inc()
			break
		}
		attempted[providerName] = struct{}{}
		metrics.AIProviderSelectedTotal.WithLabelValues(providerName).Inc()
		start := s.now()
		resp, err := provider.Explain(ctx, req)
		quota := provider.Quota(ctx)
		if quota.Provider == "" {
			quota.Provider = providerName
		}
		if s.quotas != nil {
			s.quotas.Set(quota)
		}
		s.observeQuotaMetrics(quota)
		metrics.AIProviderQuotaState.WithLabelValues(providerName).Set(float64(quotaStateValue(quota.State)))
		metrics.AIExplainLatencySeconds.WithLabelValues(providerName).Observe(time.Since(start).Seconds())
		if err == nil {
			if resp.Provider == "" {
				resp.Provider = providerName
			}
			if resp.Model == "" {
				resp.Model = modelForProvider(providerName, s.cfg)
			}
			resp.Explanation = s.redactor.Redact(resp.Explanation).Text
			resp.ContextHash = ctxHash
			if resp.QuotaState == "" {
				resp.QuotaState = string(quota.State)
			}
			if resp.Provider == "" {
				resp.Provider = providerName
			}
			tokensUsed := resp.TotalTokens
			if tokensUsed <= 0 {
				tokensUsed = resp.InputTokens + resp.OutputTokens
			}
			if tokensUsed > 0 {
				metrics.AIProviderTokensUsedTotal.WithLabelValues(providerName).Add(float64(tokensUsed))
			}
			_ = s.cache.Put(ctx, aicache.Entry{
				Key:          cacheKey,
				Provider:     resp.Provider,
				Model:        resp.Model,
				QuotaState:   resp.QuotaState,
				Explanation:  resp.Explanation,
				InputTokens:  resp.InputTokens,
				OutputTokens: resp.OutputTokens,
				TotalTokens:  resp.TotalTokens,
				AuditID:      resp.AuditID,
				ExpiresAt:    s.now().Add(s.ttlForState(quota.State)),
			})
			return resp, nil
		}
		metrics.AIExplainFailuresTotal.Inc()
		if quota.State == aiquota.Throttled || quota.State == aiquota.Exhausted || quota.State == aiquota.Cooldown {
			metrics.AIProviderRateLimitedTotal.WithLabelValues(providerName).Inc()
		} else {
			metrics.AIProviderSkippedTotal.WithLabelValues(providerName).Inc()
		}
		req.ProviderPreference = "auto"
	}
	resp := s.unavailableResponse("all AI providers are unavailable")
	resp.ContextHash = ctxHash
	s.cacheUnavailable(ctx, cacheKey, resp, aiquota.Unknown)
	return resp, nil
}

func (s *Service) cacheUnavailable(ctx context.Context, key string, resp ai.ExplainResponse, state aiquota.State) {
	_ = s.cache.Put(ctx, aicache.Entry{
		Key:         key,
		Provider:    resp.Provider,
		Model:       resp.Model,
		QuotaState:  resp.QuotaState,
		Explanation: resp.Explanation,
		AuditID:     resp.AuditID,
		ExpiresAt:   s.now().Add(s.ttlForState(state)),
	})
}

func (s *Service) observeQuotaMetrics(quota aiquota.ProviderQuota) {
	if quota.Provider == "" {
		return
	}
	if quota.RequestsLimit > 0 && quota.RequestsRemain >= 0 {
		remaining := float64(quota.RequestsRemain)
		limit := float64(quota.RequestsLimit)
		if limit > 0 {
			metrics.AIProviderQuotaRemainingPercent.WithLabelValues(quota.Provider).Set((remaining / limit) * 100)
		}
	}
	metrics.AIProviderQuotaState.WithLabelValues(quota.Provider).Set(float64(quotaStateValue(quota.State)))
}

func modelForProvider(providerName string, cfg ai.Config) string {
	switch strings.ToLower(strings.TrimSpace(providerName)) {
	case string(providers.OpenAI):
		return cfg.OpenAI.Model
	case string(providers.Anthropic):
		return cfg.Anthropic.Model
	case string(providers.Gemini):
		return cfg.Gemini.Model
	default:
		return ""
	}
}

func maxIntLocal(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func quotaStateValue(state aiquota.State) int {
	switch state {
	case aiquota.Normal:
		return 0
	case aiquota.Warning:
		return 1
	case aiquota.Throttled:
		return 2
	case aiquota.Exhausted:
		return 3
	case aiquota.Unknown:
		return 4
	case aiquota.Cooldown:
		return 5
	case aiquota.Disabled:
		return 6
	default:
		return 4
	}
}

func (s *Service) ttlForState(state aiquota.State) time.Duration {
	switch state {
	case aiquota.Warning:
		return 30 * time.Minute
	case aiquota.Throttled:
		return 60 * time.Minute
	case aiquota.Exhausted:
		return 60 * time.Minute
	case aiquota.Disabled:
		return 5 * time.Minute
	case aiquota.Unknown:
		return 5 * time.Minute
	default:
		return s.cfg.CacheTTL
	}
}

func (s *Service) normalizeRequest(req ai.ExplainRequest) ai.ExplainRequest {
	effective := req
	if pref := strings.TrimSpace(effective.ProviderPreference); pref != "" {
		effective.ProviderPreference = pref
	} else {
		effective.ProviderPreference = strings.TrimSpace(s.cfg.ProviderStrategy)
	}
	if effective.ProviderPreference == "" {
		effective.ProviderPreference = "auto"
	}
	effective.MaxContextBytes = capPositive(effective.MaxContextBytes, s.cfg.MaxContextBytes)
	effective.MaxOutputTokens = capPositive(effective.MaxOutputTokens, s.cfg.MaxOutputTokens)
	return effective
}

func capPositive(value, fallback int) int {
	switch {
	case value > 0 && fallback > 0 && value < fallback:
		return value
	case value > 0 && fallback > 0:
		return fallback
	case value > 0:
		return value
	case fallback > 0:
		return fallback
	default:
		return 1
	}
}
