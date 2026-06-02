package providers

import (
	"context"

	ai "github.com/jm/security-automation-go/internal/ai"
	aiquota "github.com/jm/security-automation-go/internal/ai/quota"
)

// Name identifies a future AI provider implementation.
type Name string

const (
	OpenAI    Name = "openai"
	Anthropic Name = "anthropic"
	Gemini    Name = "gemini"
)

// Provider is the future read-only provider contract.
// Implementations must never mutate the host or any external system.
type Provider interface {
	Name() Name
	Explain(ctx context.Context, req ai.ExplainRequest) (ai.ExplainResponse, error)
	Quota(ctx context.Context) aiquota.ProviderQuota
}
