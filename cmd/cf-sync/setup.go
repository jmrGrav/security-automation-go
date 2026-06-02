package main

import (
	"github.com/jm/security-automation-go/internal/abuseipdb"
	"github.com/jm/security-automation-go/internal/betterstack"
	"github.com/jm/security-automation-go/internal/cloudflare/client"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/httpclient"
	polmodels "github.com/jm/security-automation-go/internal/policy/models"
)

func buildPolicies(cfg *config.Config) []polmodels.Policy {
	policies := make([]polmodels.Policy, 0, len(cfg.Policies))
	for _, p := range cfg.Policies {
		policy := polmodels.Policy{
			ID:      p.ID,
			Name:    p.Name,
			Enabled: p.Enabled,
		}
		for _, r := range p.Rules {
			policy.Rules = append(policy.Rules, polmodels.Rule{
				ID:          r.ID,
				Description: r.Description,
				Target:      r.Target,
				Condition:   r.Condition,
				Decision:    polmodels.Decision(r.Decision),
			})
		}
		policies = append(policies, policy)
	}
	return policies
}

func initExternalClients(cfg *config.Config, hc httpclient.Client) (*abuseipdb.Client, *client.Client, betterstack.IngestClient) {
	cf := client.New(cfg.Cloudflare.APIToken, hc)

	var abuse *abuseipdb.Client
	if cfg.AbuseIPDB.APIKey != "" && !abuseIPDBReportingDisabled(cfg) {
		abuse = abuseipdb.NewClient(cfg.AbuseIPDB.APIKey, hc)
	}

	var betterClient betterstack.IngestClient
	if cfg.BetterStack.SourceToken != "" && cfg.BetterStack.IngestingHost != "" {
		betterClient = betterstack.NewClient(hc, cfg.BetterStack.SourceToken, cfg.BetterStack.IngestingHost)
	}

	return abuse, cf, betterClient
}
