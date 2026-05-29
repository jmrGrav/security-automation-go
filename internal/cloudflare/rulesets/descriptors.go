package rulesets

import (
	"github.com/jm/security-automation-go/internal/cloudflare/models"
)

// Standard Cloudflare WAF/Ruleset Phases
const (
	PhaseHttpRequestFirewallCustom  = "http_request_firewall_custom"
	PhaseHttpRequestFirewallManaged = "http_request_firewall_managed"
	PhaseHttpRequestRateLimit       = "http_request_ratelimit"
	PhaseHttpConfigSettings         = "http_config_settings"
)

// Registry maps phases to their evaluation precedence.
type Registry struct {
	phases map[string]models.PhaseDescriptor
}

func NewRegistry() *Registry {
	r := &Registry{
		phases: make(map[string]models.PhaseDescriptor),
	}
	r.init()
	return r
}

func (r *Registry) init() {
	r.phases[PhaseHttpRequestFirewallCustom] = models.PhaseDescriptor{
		ID:         PhaseHttpRequestFirewallCustom,
		Name:       "WAF Custom Rules",
		Precedence: 10,
	}
	r.phases[PhaseHttpRequestFirewallManaged] = models.PhaseDescriptor{
		ID:         PhaseHttpRequestFirewallManaged,
		Name:       "WAF Managed Rules",
		Precedence: 20,
	}
	r.phases[PhaseHttpRequestRateLimit] = models.PhaseDescriptor{
		ID:         PhaseHttpRequestRateLimit,
		Name:       "Rate Limiting",
		Precedence: 30,
	}
}

func (r *Registry) GetPhase(id string) (models.PhaseDescriptor, bool) {
	p, ok := r.phases[id]
	return p, ok
}
