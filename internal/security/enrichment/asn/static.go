package asn

import (
	"context"
	"net"
	"net/netip"
)

// protectedEntry is a single CIDR→(owner, kind) mapping used at runtime.
type protectedEntry struct {
	net   *net.IPNet
	owner string
	kind  Kind
}

// StaticProvider classifies IPs against a compiled list of well-known CIDR
// ranges. No subprocess, no external API call; completely offline.
//
// Classification priority (first match wins):
//   - Protected networks  → kind set per registry entry + Protected=true
//   - Unrecognised ranges → KindUnknown + Protected=false
type StaticProvider struct {
	protected []protectedEntry
}

// NewStaticProvider returns a provider built from DefaultRegistry().
// Only entries with at least one CIDR are loaded into the runtime table.
func NewStaticProvider() *StaticProvider {
	return NewStaticProviderFromRegistry(DefaultRegistry())
}

// NewStaticProviderFromRegistry builds a StaticProvider from the given registry
// entries. Entries with empty CIDRs (status != loaded) are skipped.
func NewStaticProviderFromRegistry(entries []RegistryEntry) *StaticProvider {
	var protected []protectedEntry
	for _, e := range entries {
		for _, cidrStr := range e.CIDRs {
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				continue
			}
			protected = append(protected, protectedEntry{
				net:   ipNet,
				owner: e.Organization,
				kind:  e.Kind,
			})
		}
	}
	return &StaticProvider{protected: protected}
}

func (p *StaticProvider) Name() string { return "static" }

func (p *StaticProvider) Lookup(_ context.Context, ip netip.Addr) (Result, error) {
	stdIP := net.IP(ip.Unmap().AsSlice())
	for _, entry := range p.protected {
		if entry.net.Contains(stdIP) {
			return Result{
				Provider:  "static",
				Kind:      entry.kind,
				Org:       entry.owner,
				Network:   entry.net.String(),
				Protected: true,
			}, nil
		}
	}
	return Result{
		Provider: "static",
		Kind:     KindUnknown,
	}, nil
}
