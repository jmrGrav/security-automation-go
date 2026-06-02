package virustotal

import (
	"context"
	"net/netip"

	"github.com/jm/security-automation-go/internal/security/enrichment"
)

type Client interface {
	Name() string
	Mode() enrichment.LookupMode
	Lookup(ctx context.Context, ip netip.Addr) (enrichment.ProviderVerdict, error)
}
