package main

import (
	"time"

	"github.com/jm/security-automation-go/internal/abuseipdb"
	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
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

func newWAFReplayService(cf *client.Client, abuse *abuseipdb.Client, telemetry sinks.Sink, trustRegistry *sectrust.Registry, cfg *config.Config, stores *sqlite.ReportingStores) *cloudflareevent.Service {
	if abuse == nil {
		return nil
	}
	reportingService := reporting.New(abuse.Executor, telemetry, trustRegistry, cfg.AbuseIPDB.CacheTTL)
	if stores != nil {
		stores.Configure(reportingService)
	}
	return cloudflareevent.NewService(cf, reportingService)
}
