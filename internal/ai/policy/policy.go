package policy

import (
	"context"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/ai/providers"
	aiquota "github.com/jm/security-automation-go/internal/ai/quota"
)

// Decision records the read-only policy outcome for a future explain request.
type Decision struct {
	Allowed bool
	Reason  string
}

// Policy evaluates whether a provider can safely be used for an explain request.
type Policy interface {
	Allow(ctx context.Context, req ai.ExplainRequest, quota aiquota.ProviderQuota) (Decision, error)
}

// ProviderPolicy evaluates provider-specific read-only safety and quota posture.
type ProviderPolicy interface {
	AllowProvider(ctx context.Context, provider providers.Provider, req ai.ExplainRequest, quota aiquota.ProviderQuota) (Decision, error)
}
