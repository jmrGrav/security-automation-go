// Package trust protects critical resources from automatic security actions.
// The defaults are intentionally conservative and bias toward under-blocking
// rather than catastrophic over-blocking.
package trust

import (
	"net/netip"
	"slices"
	"sort"
	"strings"
)

type ProtectedResource struct {
	Name             string   `json:"name"`
	Kind             string   `json:"kind"`
	CIDR             string   `json:"cidr,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	MinConfidence    float64  `json:"min_confidence"`
	AllowPropagation bool     `json:"allow_propagation"`
}

type Match struct {
	Resource ProtectedResource `json:"resource"`
	Reason   string            `json:"reason"`
}

type Registry struct {
	resources []ProtectedResource
	prefixes  []prefixResource
}

type prefixResource struct {
	prefix   netip.Prefix
	resource ProtectedResource
}

func DefaultRegistry() *Registry {
	r := &Registry{}
	for _, item := range []ProtectedResource{
		{Name: "rfc1918-10", Kind: "network", CIDR: "10.0.0.0/8", Tags: []string{"internal", "rfc1918"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "rfc1918-172", Kind: "network", CIDR: "172.16.0.0/12", Tags: []string{"internal", "rfc1918"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "rfc1918-192", Kind: "network", CIDR: "192.168.0.0/16", Tags: []string{"internal", "rfc1918"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "loopback-v4", Kind: "network", CIDR: "127.0.0.0/8", Tags: []string{"loopback"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "loopback-v6", Kind: "network", CIDR: "::1/128", Tags: []string{"loopback"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "link-local-v4", Kind: "network", CIDR: "169.254.0.0/16", Tags: []string{"linklocal"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "link-local-v6", Kind: "network", CIDR: "fe80::/10", Tags: []string{"linklocal"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "cloudflare-173", Kind: "network", CIDR: "173.245.48.0/20", Tags: []string{"cloudflare", "edge"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "cloudflare-103-21", Kind: "network", CIDR: "103.21.244.0/22", Tags: []string{"cloudflare", "edge"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "cloudflare-103-22", Kind: "network", CIDR: "103.22.200.0/22", Tags: []string{"cloudflare", "edge"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "cloudflare-103-31", Kind: "network", CIDR: "103.31.4.0/22", Tags: []string{"cloudflare", "edge"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "cloudflare-141", Kind: "network", CIDR: "141.101.64.0/18", Tags: []string{"cloudflare", "edge"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "cloudflare-108", Kind: "network", CIDR: "108.162.192.0/18", Tags: []string{"cloudflare", "edge"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "cloudflare-190", Kind: "network", CIDR: "190.93.240.0/20", Tags: []string{"cloudflare", "edge"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "cloudflare-188", Kind: "network", CIDR: "188.114.96.0/20", Tags: []string{"cloudflare", "edge"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "cloudflare-197", Kind: "network", CIDR: "197.234.240.0/22", Tags: []string{"cloudflare", "edge"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "cloudflare-198", Kind: "network", CIDR: "198.41.128.0/17", Tags: []string{"cloudflare", "edge"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "cloudflare-162", Kind: "network", CIDR: "162.158.0.0/15", Tags: []string{"cloudflare", "edge"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "cloudflare-104-16", Kind: "network", CIDR: "104.16.0.0/13", Tags: []string{"cloudflare", "edge"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "cloudflare-104-24", Kind: "network", CIDR: "104.24.0.0/14", Tags: []string{"cloudflare", "edge"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "cloudflare-172", Kind: "network", CIDR: "172.64.0.0/13", Tags: []string{"cloudflare", "edge"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "cloudflare-131", Kind: "network", CIDR: "131.0.72.0/22", Tags: []string{"cloudflare", "edge"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "control-plane", Kind: "service", Tags: []string{"management", "control-plane"}, MinConfidence: 1.0, AllowPropagation: false},
		{Name: "monitoring", Kind: "service", Tags: []string{"monitoring"}, MinConfidence: 0.98, AllowPropagation: false},
		{Name: "sonarr", Kind: "service", Tags: []string{"media", "critical"}, MinConfidence: 0.98, AllowPropagation: false},
		{Name: "radarr", Kind: "service", Tags: []string{"media", "critical"}, MinConfidence: 0.98, AllowPropagation: false},
	} {
		r.Add(item)
	}
	return r
}

func (r *Registry) Add(resource ProtectedResource) {
	r.resources = append(r.resources, resource)
	if resource.CIDR != "" {
		if prefix, err := netip.ParsePrefix(resource.CIDR); err == nil {
			r.prefixes = append(r.prefixes, prefixResource{prefix: prefix, resource: resource})
		}
	}
}

func (r *Registry) MatchIP(ip string) []Match {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	matches := make([]Match, 0, 2)
	for _, item := range r.prefixes {
		if item.prefix.Contains(addr) {
			matches = append(matches, Match{
				Resource: item.resource,
				Reason:   "protected network",
			})
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Resource.Name < matches[j].Resource.Name })
	return matches
}

func (r *Registry) MatchService(name string) []Match {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return nil
	}
	matches := make([]Match, 0, 2)
	for _, item := range r.resources {
		if item.Kind != "service" {
			continue
		}
		if strings.EqualFold(item.Name, name) || slices.Contains(item.Tags, name) {
			matches = append(matches, Match{
				Resource: item,
				Reason:   "protected service",
			})
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Resource.Name < matches[j].Resource.Name })
	return matches
}
