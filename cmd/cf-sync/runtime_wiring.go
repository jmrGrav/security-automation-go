package main

import (
	"time"

	"github.com/jm/security-automation-go/internal/abuseipdb"
	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	crowdsecevent "github.com/jm/security-automation-go/internal/adapters/crowdsecevent"
	openrestyevent "github.com/jm/security-automation-go/internal/adapters/openrestyevent"
	"github.com/jm/security-automation-go/internal/betterstack"
	"github.com/jm/security-automation-go/internal/cloudflare/client"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/execution"
	fp_memory "github.com/jm/security-automation-go/internal/security/fp_memory"
	"github.com/jm/security-automation-go/internal/security/reputation"
	sectrust "github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

func newSecurityTelemetry(cfg *config.Config, betterClient betterstack.IngestClient) sinks.Sink {
	if cfg.BetterStack.SourceToken != "" && cfg.BetterStack.IngestingHost != "" && betterClient != nil {
		return sinks.NewMulti(
			sinks.NewPrometheus(),
			sinks.NewBetterStack(betterClient),
		)
	}
	return sinks.NewMulti(sinks.NewPrometheus())
}

func abuseIPDBReportingDisabled(cfg *config.Config) bool {
	return cfg != nil && cfg.AbuseIPDB.ReportingEnabled != nil && !*cfg.AbuseIPDB.ReportingEnabled
}

func configureSecurityGuard(exec *execution.GovernedExecutor, checker reputation.Checker, trustRegistry *sectrust.Registry, cfg *config.Config) {
	guard := execution.NewCloudflarePropagationGuard(checker, trustRegistry)
	guard.SetFalsePositiveMemory(fp_memory.New(24 * time.Hour))
	guard.SetThreshold(cfg.AbuseIPDB.Threshold)
	guard.SetFailureMode(reputation.FailureMode(cfg.AbuseIPDB.FailureMode))
	exec.SetSecurityGuard(guard)
}

// wafBundle groups all WAF event services that share a single reporting.Service.
// Sharing ensures a single dedup store and a single evidence store across all
// three sources (Cloudflare WAF, CrowdSec, OpenResty).
type wafBundle struct {
	cfWAF    *cloudflareevent.Service
	csSource *crowdsecevent.LiveSource
	cs       *crowdsecevent.Service
	orSource *openrestyevent.LiveSource
	or       *openrestyevent.Service
}

// newWAFBundle creates all WAF event services sharing one reporting.Service.
// Returns nil when AbuseIPDB is not configured (abuse == nil).
func newWAFBundle(cf *client.Client, abuse *abuseipdb.Client, telemetry sinks.Sink, trustRegistry *sectrust.Registry, cfg *config.Config, stores *sqlite.ReportingStores) *wafBundle {
	if abuse == nil {
		return nil
	}
	svc := reporting.New(abuse.Executor, telemetry, trustRegistry, cfg.AbuseIPDB.CacheTTL)
	if stores != nil {
		stores.Configure(svc)
	}
	return &wafBundle{
		cfWAF:    cloudflareevent.NewService(cf, svc),
		csSource: crowdsecevent.NewLiveSource(cfg.CrowdSec.DecisionsLog, cfg.CrowdSec.NginxLogDir, 24*time.Hour),
		cs:       crowdsecevent.NewService(svc),
		orSource: openrestyevent.NewLiveSource(cfg.OpenResty.EventsFile),
		or:       openrestyevent.NewService(svc),
	}
}

// cfWAFService returns the Cloudflare WAF service, or nil when the bundle is nil.
func (b *wafBundle) cfWAFService() *cloudflareevent.Service {
	if b == nil {
		return nil
	}
	return b.cfWAF
}
