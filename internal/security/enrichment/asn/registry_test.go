package asn_test

import (
	"net"
	"testing"

	"github.com/jm/security-automation-go/internal/security/enrichment/asn"
)

// TestRegistry_AllCIDRsAreValid ensures every CIDR string in the default registry
// parses without error. An unparseable CIDR silently falls through in the static
// provider; this test makes silent failures loud.
func TestRegistry_AllCIDRsAreValid(t *testing.T) {
	for _, entry := range asn.DefaultRegistry() {
		for _, cidr := range entry.CIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				t.Errorf("org=%q: invalid CIDR %q: %v", entry.Organization, cidr, err)
			}
		}
	}
}

// TestRegistry_LoadedEntriesHaveSourceURL documents the requirement that every
// entry with CIDRs (status=loaded) must declare a SourceURL for auditability.
func TestRegistry_LoadedEntriesHaveSourceURL(t *testing.T) {
	for _, entry := range asn.DefaultRegistry() {
		if len(entry.CIDRs) > 0 && entry.SourceURL == "" {
			t.Errorf("org=%q: has %d CIDRs but no SourceURL — all loaded entries require a verifiable source",
				entry.Organization, len(entry.CIDRs))
		}
	}
}

// TestRegistry_KindNeverEmpty ensures every registry entry has a non-empty Kind.
func TestRegistry_KindNeverEmpty(t *testing.T) {
	for _, entry := range asn.DefaultRegistry() {
		if entry.Kind == "" {
			t.Errorf("org=%q: Kind must not be empty", entry.Organization)
		}
	}
}

// TestRegistry_NoCIDRsForSourceUnavailable ensures that entries with no source URL
// carry no CIDRs — a sanity check against accidental addition without documentation.
func TestRegistry_NoCIDRsForSourceUnavailable(t *testing.T) {
	for _, entry := range asn.DefaultRegistry() {
		if entry.SourceURL == "" && len(entry.CIDRs) > 0 {
			t.Errorf("org=%q: has CIDRs but no SourceURL — add the authoritative source URL first",
				entry.Organization)
		}
	}
}

// TestRegistry_Status verifies the status derivation rules for known entries.
func TestRegistry_Status(t *testing.T) {
	cases := []struct {
		org    string
		expect asn.RegistryStatus
	}{
		{"cloudflare", asn.RegistryStatusLoaded},
		{"openai-gptbot", asn.RegistryStatusLoaded},
		{"openai-searchbot", asn.RegistryStatusLoaded},
		{"github-copilot", asn.RegistryStatusLoaded},
		{"openai-chatgpt-user", asn.RegistryStatusTooVolatile},
		{"anthropic", asn.RegistryStatusLoaded},
	}

	idx := make(map[string]asn.RegistryEntry)
	for _, e := range asn.DefaultRegistry() {
		idx[e.Organization] = e
	}

	for _, tc := range cases {
		e, ok := idx[tc.org]
		if !ok {
			t.Errorf("org=%q not found in registry", tc.org)
			continue
		}
		if got := e.Status(); got != tc.expect {
			t.Errorf("org=%q: expected status %q, got %q", tc.org, tc.expect, got)
		}
	}
}
