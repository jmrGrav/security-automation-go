package gateway

import (
	"context"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/ai/providers"
)

// ProviderRouter selects a read-only provider for an explain request.
type ProviderRouter interface {
	SelectProvider(ctx context.Context, req ai.ExplainRequest) (providers.Provider, error)
}

// Gateway is the future read-only AI explain entrypoint.
type Gateway interface {
	Explain(ctx context.Context, req ai.ExplainRequest) (ai.ExplainResponse, error)
}
