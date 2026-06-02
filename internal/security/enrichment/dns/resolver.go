package dns

import (
	"context"
	"net"
)

// NetResolver wraps net.DefaultResolver so tests can inject a fake resolver
// while production uses the system resolver directly (no subprocess).
type NetResolver struct {
	inner *net.Resolver
}

// NewNetResolver returns a resolver backed by the system default resolver.
func NewNetResolver() *NetResolver {
	return &NetResolver{inner: net.DefaultResolver}
}

func (r *NetResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return r.inner.LookupAddr(ctx, addr)
}

func (r *NetResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return r.inner.LookupHost(ctx, host)
}
