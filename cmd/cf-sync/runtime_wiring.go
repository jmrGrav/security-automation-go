package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/abuseipdb"
	abexec "github.com/jm/security-automation-go/internal/abuseipdb/executor"
	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	abtransport "github.com/jm/security-automation-go/internal/abuseipdb/transport"
	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	crowdsecevent "github.com/jm/security-automation-go/internal/adapters/crowdsecevent"
	openrestyevent "github.com/jm/security-automation-go/internal/adapters/openrestyevent"
	"github.com/jm/security-automation-go/internal/betterstack"
	cfpkg "github.com/jm/security-automation-go/internal/cloudflare"
	"github.com/jm/security-automation-go/internal/cloudflare/client"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/execution"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/runtime/providerstate"
	fp_memory "github.com/jm/security-automation-go/internal/security/fp_memory"
	"github.com/jm/security-automation-go/internal/security/reputation"
	sectrust "github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/autoban"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

// buildTrustRegistry returns a trust.Registry seeded with defaults plus any
// operator-protected hosts from cfg.Global.ProtectedHosts.
func buildTrustRegistry(cfg *config.Config) *sectrust.Registry {
	r := sectrust.DefaultRegistry()
	if cfg == nil {
		return r
	}
	for _, host := range cfg.Global.ProtectedHosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		cidr := host
		if !strings.Contains(host, "/") {
			cidr = host + "/32"
		}
		r.Add(sectrust.ProtectedResource{
			Name:             "operator-host-" + host,
			Kind:             "host",
			CIDR:             cidr,
			Tags:             []string{"operator", "protected"},
			MinConfidence:    1.0,
			AllowPropagation: false,
		})
	}
	return r
}

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
	banEval  *autoban.Evaluator
	banExec  autoban.BanExecutor
}

// newWAFBundle creates all WAF event services sharing one reporting.Service.
// The reporting executor is runtime-gated so AbuseIPDB can be enabled/disabled
// and retested without restarting the binary.
func newWAFBundle(cf *client.Client, abuse *abuseipdb.Client, hc httpclient.Client, creds credentialLooker, stateStore providerstate.Store, telemetry sinks.Sink, trustRegistry *sectrust.Registry, cfg *config.Config, stores *sqlite.ReportingStores, logger *slog.Logger) *wafBundle {
	reportExecutor := newRuntimeAbuseExecutor(hc, creds, stateStore, cfg != nil && cfg.AbuseIPDB.Enabled, abuse)
	svc := reporting.New(reportExecutor, telemetry, trustRegistry, cfg.AbuseIPDB.CacheTTL)
	if stores != nil {
		stores.Configure(svc)
	}
	// Build the auto-ban evaluator using the AbuseIPDB key known at startup.
	// A nil key disables the confidence-100 rule (fail-open); burst rule still works.
	var abuseKey string
	if creds != nil {
		if k, ok, _ := creds.Lookup(context.Background(), "abuseipdb.api_key"); ok {
			abuseKey = k
		}
	}
	banEval := buildAutoBanEvaluator(cfg, hc, trustRegistry, abuseKey, logger)
	var banExec autoban.BanExecutor
	if cfg != nil && cfg.Cloudflare.MutationsEnabled && cfg.Cloudflare.AutoBanEnabled {
		cfEnforcer := cfpkg.NewClient(hc, cfg.Cloudflare.APIToken)
		banExec = &cfBanExecutor{client: cfEnforcer, zoneID: cfg.Cloudflare.ZoneID, logger: logger}
	}
	return &wafBundle{
		cfWAF:    cloudflareevent.NewService(cf, svc),
		csSource: crowdsecevent.NewLiveSource(cfg.CrowdSec.DecisionsLog, cfg.CrowdSec.NginxLogDir, 24*time.Hour),
		cs:       crowdsecevent.NewService(svc),
		orSource: openrestyevent.NewLiveSource(cfg.OpenResty.EventsFile),
		or:       openrestyevent.NewService(svc),
		banEval:  banEval,
		banExec:  banExec,
	}
}

func newRuntimeAbuseExecutor(hc httpclient.Client, creds credentialLooker, stateStore providerstate.Store, fallbackEnabled bool, initial *abuseipdb.Client) abexec.Executor {
	executor := &runtimeAbuseExecutor{
		hc:              hc,
		credentialStore: creds,
		stateStore:      stateStore,
		fallbackEnabled: fallbackEnabled,
	}
	if initial != nil {
		executor.executor = initial.Executor
	}
	return executor
}

type runtimeAbuseExecutor struct {
	hc              httpclient.Client
	credentialStore credentialLooker
	stateStore      providerstate.Store
	fallbackEnabled bool

	mu       sync.Mutex
	key      string
	executor abexec.Executor
}

func (r *runtimeAbuseExecutor) Execute(ctx context.Context, reports []abmodels.ExecutableReport) error {
	if r == nil {
		return nil
	}
	if !runtimeProviderEnabled(ctx, r.stateStore, "abuseipdb", r.fallbackEnabled) {
		return nil
	}
	key := r.currentKey(ctx)
	if key == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.executor == nil || r.key != key {
		r.key = key
		if r.hc == nil {
			return nil
		}
		r.executor = abexec.New(abtransport.New(r.hc, key))
	}
	if r.executor == nil {
		return nil
	}
	return r.executor.Execute(ctx, reports)
}

func (r *runtimeAbuseExecutor) currentKey(ctx context.Context) string {
	if r == nil || r.credentialStore == nil {
		return ""
	}
	if v, ok, err := r.credentialStore.Lookup(ctx, "abuseipdb.api_key"); err == nil && ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func runtimeProviderEnabled(ctx context.Context, store providerstate.Store, slug string, fallback bool) bool {
	if store == nil {
		return fallback
	}
	state, ok, err := providerstate.Load(ctx, store, slug)
	if err != nil || !ok {
		return fallback
	}
	return state.Enabled
}

// cfWAFService returns the Cloudflare WAF service, or nil when the bundle is nil.
func (b *wafBundle) cfWAFService() *cloudflareevent.Service {
	if b == nil {
		return nil
	}
	return b.cfWAF
}

// banEvalService returns the auto-ban evaluator, or nil when the bundle is nil.
func (b *wafBundle) banEvalService() *autoban.Evaluator {
	if b == nil {
		return nil
	}
	return b.banEval
}

// banExecutorService returns the CF ban executor, or nil when in shadow mode.
func (b *wafBundle) banExecutorService() autoban.BanExecutor {
	if b == nil {
		return nil
	}
	return b.banExec
}

// transportAbuseChecker wraps the AbuseIPDB transport to satisfy autoban.AbuseIPDBChecker.
type transportAbuseChecker struct {
	t *abtransport.Transport
}

func (c *transportAbuseChecker) CheckScore(ctx context.Context, ip string) (int, error) {
	resp, err := c.t.Check(ctx, ip)
	if err != nil {
		return 0, err
	}
	return resp.Data.AbuseConfidenceScore, nil
}

// buildAutoBanEvaluator constructs an auto-ban evaluator for the daemon WAF replay.
// When no AbuseIPDB key is available the confidence-100 rule is disabled (fail-open).
// When cfg.Cloudflare.MutationsEnabled is false the evaluator runs in shadow mode
// (logs decisions but never mutates Cloudflare).
func buildAutoBanEvaluator(cfg *config.Config, hc httpclient.Client, trustReg *sectrust.Registry, abuseKey string, logger *slog.Logger) *autoban.Evaluator {
	var enricher autoban.IPEnricher
	if abuseKey != "" {
		checker := &transportAbuseChecker{t: abtransport.New(hc, abuseKey)}
		enricher = autoban.NewCachedEnricher(checker, 6*time.Hour)
	}
	// Live mode requires both Cloudflare mutations and the explicit auto-ban flag.
	liveMode := cfg != nil && cfg.Cloudflare.MutationsEnabled && cfg.Cloudflare.AutoBanEnabled
	return autoban.NewEvaluator(autoban.Config{LiveMode: liveMode}, trustReg, enricher, logger)
}

// cfBanExecutor enacts ban decisions by creating a Cloudflare IP access rule.
// It is only instantiated when both mutations_enabled and auto_ban_enabled are set.
type cfBanExecutor struct {
	client cfpkg.EnforcementClient
	zoneID string
	logger *slog.Logger
}

func (e *cfBanExecutor) ExecuteBan(ctx context.Context, decision autoban.BanDecision) error {
	if e == nil || e.client == nil {
		return nil
	}
	tag := fmt.Sprintf("cf-sync:autoban:%s", decision.Reason)
	id, err := e.client.AddIPAccessRule(ctx, e.zoneID, decision.IP, tag, "ip")
	if err != nil {
		if e.logger != nil {
			e.logger.Error("autoban: CF ban failed", "ip", decision.IP, "reason", decision.Reason, "error", err)
		}
		return err
	}
	if e.logger != nil {
		e.logger.Info("autoban: CF ban applied", "ip", decision.IP, "reason", decision.Reason, "rule_id", id)
	}
	return nil
}
