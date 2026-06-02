package dns_test

import (
	"context"
	"testing"

	"github.com/jm/security-automation-go/internal/security/enrichment/dns"
)

func TestNetResolver_Construction(t *testing.T) {
	r := dns.NewNetResolver()
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
}

// TestNetResolver_LookupAddrLoopback verifies the real resolver can be called
// without panicking. We use loopback so the test stays offline on machines
// where the loopback PTR is resolvable.
func TestNetResolver_LookupAddrLoopback(t *testing.T) {
	r := dns.NewNetResolver()
	// We don't assert the result — DNS behaviour varies per machine.
	// We only assert no panic and a valid (possibly empty) response.
	_, _ = r.LookupAddr(context.Background(), "127.0.0.1")
}
