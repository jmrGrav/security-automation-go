package spamhaus

import (
	"context"
	"net/netip"
)

type Client interface {
	Report(ctx context.Context, ip netip.Addr, reason string) error
}
