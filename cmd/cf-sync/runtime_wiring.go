package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/abuseipdb"
	abexec "github.com/jm/security-automation-go/internal/abuseipdb/executor"
	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	abtransport "github.com/jm/security-automation-go/internal/abuseipdb/transport"
	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	crowdsecevent "github.com/jm/security-automation-go/internal/adapters/crowdsecevent"
	"github.com/jm/security-automation-go/internal/adapters/nginxerrors"
	openrestyevent "github.com/jm/security-automation-go/internal/adapters/openrestyevent"
	"github.com/jm/security-automation-go/internal/adapters/wafref"
	"github.com/jm/security-automation-go/internal/betterstack"
	cfpkg "github.com/jm/security-automation-go/internal/cloudflare"
	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
	"github.com/jm/security-automation-go/internal/cloudflare/client"
	"github.com/jm/security-automation-go/internal/cloudflare/enforcementlog"
	"github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/execution"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/runtime/providerstate"
	"github.com/jm/security-automation-go/internal/security/enrichment/spamhaus"
	fp_memory "github.com/jm/security-automation-go/internal/security/fp_memory"
	"github.com/jm/security-automation-go/internal/security/quota"
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
	wrSource *wafref.LiveSource
	wr       *wafref.Service
	erSource *nginxerrors.LiveSource
	er       *nginxerrors.Service
	banEval  *autoban.Evaluator
	banExec  autoban.BanExecutor

	// banLifecycleStore is exposed so the daemon can start the cleanup
	// worker against the same store the ban executor writes to.
	banLifecycleStore banlifecycle.Store

	// enforcementEventStore is exposed so the daemon can wire the same
	// event log the ban executor writes to into the cleanup worker's
	// audit/CF-client adapters, giving /sync a single real-time stream of
	// every ban/deban attempt (success and failure).
	enforcementEventStore enforcementlog.Store

	// repGate is exposed so the daemon can also wire it into the autodeban
	// scanner (it must be the SAME gate instance svc/banEval consult, so
	// shadow/enforce mode and provider signals stay consistent everywhere).
	repGate *reputation.Gate
}

// newWAFBundle creates all WAF event services sharing one reporting.Service.
// The reporting executor is runtime-gated so AbuseIPDB can be enabled/disabled
// and retested without restarting the binary. lifecycleStore may be nil when
// SQLite is unavailable; ban creation still works but autoban rules will
// never be auto-expired in that degraded mode.
func newWAFBundle(cf *client.Client, abuse *abuseipdb.Client, hc httpclient.Client, creds credentialLooker, stateStore providerstate.Store, telemetry sinks.Sink, trustRegistry *sectrust.Registry, cfg *config.Config, stores *sqlite.ReportingStores, lifecycleStore banlifecycle.Store, eventStore enforcementlog.Store, logger *slog.Logger) *wafBundle {
	reportExecutor := newRuntimeAbuseExecutor(hc, creds, stateStore, cfg != nil && cfg.AbuseIPDB.Enabled, abuse)
	svc := reporting.New(reportExecutor, telemetry, trustRegistry, cfg.AbuseIPDB.CacheTTL)
	if stores != nil {
		stores.Configure(svc)
	}
	// Wire Spamhaus Submit independently of AbuseIPDB.
	// Key is read from credential store at startup; nil key disables submission (fail-open).
	if creds != nil {
		if shKey, ok, _ := creds.Lookup(context.Background(), "spamhaus.api_key"); ok && shKey != "" {
			if runtimeProviderEnabled(context.Background(), stateStore, "spamhaus", cfg != nil && cfg.Spamhaus.Enabled) {
				svc.SetSpamhausClient(spamhaus.NewSubmitClient(hc, shKey))
			}
		}
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

	// Reputation gate: built unconditionally (even with no AbuseIPDB key —
	// FetchSignals degrades to Available=false and the Gate's Evaluate
	// fail-open path still applies its own local-evidence-only logic) and
	// wired into BOTH the reporting service (report path) and the autoban
	// evaluator (ban path) so neither ever fires on AbuseIPDB/VirusTotal
	// alone. cfg.ReputationPolicy.EffectiveMode() is the single choke point
	// for shadow/enforce — see config.ReputationPolicyConfig's safety
	// invariant doc comment.
	repPolicy := reputationPolicyFromConfig(cfg)
	var gateEnricher reputation.Enricher
	if abuseKey != "" {
		checker := &transportAbuseChecker{t: abtransport.New(hc, abuseKey)}
		gateEnricher = autoban.NewCachedEnricher(checker, 6*time.Hour)
	}
	repGate := reputation.NewGate(gateEnricher, quota.DefaultRegistry(), repPolicy)
	svc.SetReputationGate(repGate)
	banEval.SetReputationGate(repGate)

	var banExec autoban.BanExecutor
	if cfg != nil && cfg.Cloudflare.MutationsEnabled && cfg.Cloudflare.AutoBanEnabled {
		cfEnforcer := cfpkg.NewClient(hc, cfg.Cloudflare.APIToken)
		banExec = &cfBanExecutor{
			client:         cfEnforcer,
			zoneID:         cfg.Cloudflare.ZoneID,
			logger:         logger,
			lifecycleStore: lifecycleStore,
			eventStore:     eventStore,
			durations:      banlifecycle.DefaultDurationPolicy(),
		}
	}
	bundle := &wafBundle{
		cfWAF:                 cloudflareevent.NewService(cf, svc),
		csSource:              crowdsecevent.NewLiveSource(cfg.CrowdSec.DecisionsLog, cfg.CrowdSec.NginxLogDir, 24*time.Hour),
		cs:                    crowdsecevent.NewService(svc),
		orSource:              openrestyevent.NewLiveSource(cfg.OpenResty.EventsFile),
		or:                    openrestyevent.NewService(svc),
		wrSource:              wafref.NewLiveSource(cfg.OpenResty.WAFRefsFile),
		wr:                    wafref.NewService(svc),
		banEval:               banEval,
		banExec:               banExec,
		banLifecycleStore:     lifecycleStore,
		enforcementEventStore: eventStore,
		repGate:               repGate,
	}
	if cfg.HTTPErrorIntel.Enabled {
		erSource := nginxerrors.NewLiveSource(cfg.CrowdSec.NginxLogDir)
		erSvc := nginxerrors.NewService(erSource, svc)
		erSvc.SetMinBurst(cfg.HTTPErrorIntel.MinBurst)
		// EnforceMode is the standing-rule opt-in: WAF/HTTP-error signals never
		// reach the auto-ban evaluator unless an operator explicitly sets this.
		// banEval still applies its own shadow/trust/dedup guards regardless.
		if cfg.HTTPErrorIntel.EnforceMode && banEval != nil {
			erSvc.SetEnforcement(banEval, banExec, cfg.HTTPErrorIntel.BanThreshold)
		}
		bundle.erSource = erSource
		bundle.er = erSvc
	}
	return bundle
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

// banLifecycleStoreService returns the Cloudflare autoban lifecycle store, or
// nil when SQLite is unavailable.
func (b *wafBundle) banLifecycleStoreService() banlifecycle.Store {
	if b == nil {
		return nil
	}
	return b.banLifecycleStore
}

// enforcementEventStoreService returns the Cloudflare enforcement event log,
// or nil when the bundle is nil.
func (b *wafBundle) enforcementEventStoreService() enforcementlog.Store {
	if b == nil {
		return nil
	}
	return b.enforcementEventStore
}

// reputationGateService returns the shared reputation gate, or nil when the
// bundle itself is nil.
func (b *wafBundle) reputationGateService() *reputation.Gate {
	if b == nil {
		return nil
	}
	return b.repGate
}

// reputationPolicyFromConfig converts the YAML-driven
// config.ReputationPolicyConfig into the pure reputation.Policy the Gate
// consumes. EffectiveMode() is the single safety choke point: Mode is
// "enforce" only on that exact literal, "shadow" for anything else
// (including a missing/omitted block) — this function must never bypass it.
func reputationPolicyFromConfig(cfg *config.Config) reputation.Policy {
	if cfg == nil {
		return reputation.DefaultPolicy()
	}
	rp := cfg.ReputationPolicy
	return reputation.Policy{
		Enabled: rp.Enabled,
		Mode:    reputation.Mode(rp.EffectiveMode()),

		AbuseIPDBCheckBeforeReport:     rp.AbuseIPDB.CheckBeforeReport,
		AbuseIPDBMinConfidenceToReport: rp.AbuseIPDB.MinConfidenceToReport,
		AbuseIPDBMinConfidenceToBan:    rp.AbuseIPDB.MinConfidenceToBan,
		AbuseIPDBSuppressIfZero:        rp.AbuseIPDB.SuppressIfConfidenceZero,

		VirusTotalEnabled:       rp.VirusTotal.Enabled,
		VirusTotalSuppressClean: rp.VirusTotal.SuppressIfClean,
	}
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
//
// On success it also records a banlifecycle.Entry (when a store is wired)
// so the recidive-aware cleanup worker can later expire and remove the
// rule. lifecycleStore may be nil (e.g. SQLite unavailable); in that case
// ExecuteBan still creates the Cloudflare rule but no lifecycle bookkeeping
// happens and the rule will never be auto-cleaned — operators must rely on
// the existing manual/CrowdSec cleanup paths in that degraded mode.
//
// When Cloudflare reports the IP already has a live rule (error code 10009,
// "duplicate_of_existing" — e.g. after a restart re-attempts a ban that was
// already applied in a prior process lifetime), ExecuteBan treats this as
// idempotent success rather than a failure: the desired end state (the IP is
// blocked) already holds. It resolves the existing rule's ID via
// ListIPAccessRulesByNotePrefix and backfills/updates a banlifecycle.Entry
// for it, so callers' "RecordBan only after ExecuteBan returns nil" pattern
// marks the IP as banned in the dedup store and stops the retry storm that
// would otherwise re-attempt this same IP on every poll cycle indefinitely.
type cfBanExecutor struct {
	client         cfpkg.EnforcementClient
	zoneID         string
	logger         *slog.Logger
	lifecycleStore banlifecycle.Store
	eventStore     enforcementlog.Store
	durations      banlifecycle.DurationPolicy
	now            func() time.Time
}

// recordEnforcementEvent is a best-effort write to eventStore: a failure to
// log must never fail or alter the outcome of ExecuteBan itself, mirroring
// how lifecycleStore.Upsert errors are only logged, never propagated.
func (e *cfBanExecutor) recordEnforcementEvent(ctx context.Context, ev enforcementlog.Event) {
	if e == nil || e.eventStore == nil {
		return
	}
	if err := e.eventStore.Append(ctx, ev); err != nil && e.logger != nil {
		e.logger.Warn("autoban: enforcement event log append failed", "ip", ev.IP, "action", ev.Action, "error", err)
	}
}

func (e *cfBanExecutor) ExecuteBan(ctx context.Context, decision autoban.BanDecision) error {
	if e == nil || e.client == nil {
		return nil
	}
	now := time.Now
	if e.now != nil {
		now = e.now
	}
	callStart := now()
	createdAt := callStart.UTC()

	recidiveLevel := 1
	if e.lifecycleStore != nil {
		if priorBans, err := e.lifecycleStore.RecidiveLevel(ctx, decision.IP); err == nil {
			recidiveLevel = priorBans + 1
		} else if e.logger != nil {
			e.logger.Warn("autoban: recidive level lookup failed, defaulting to 1", "ip", decision.IP, "error", err)
		}
	}
	durations := e.durations
	if durations == (banlifecycle.DurationPolicy{}) {
		durations = banlifecycle.DefaultDurationPolicy()
	}
	duration := durations.DurationFor(recidiveLevel)
	expiresAt := createdAt.Add(duration)

	tag := fmt.Sprintf("cf-sync:autoban:%s:exp=%s", decision.Reason, expiresAt.Format(time.RFC3339))
	id, err := e.client.AddIPAccessRule(ctx, e.zoneID, decision.IP, tag, "ip")
	if err != nil {
		if !isCFDuplicateRuleError(err) {
			if e.logger != nil {
				e.logger.Error("autoban: CF ban failed", "ip", decision.IP, "reason", decision.Reason, "error", err)
			}
			e.recordEnforcementEvent(ctx, enforcementlog.Event{
				OccurredAt: createdAt,
				Action:     enforcementlog.ActionBanFailed,
				IP:         decision.IP,
				Reason:     decision.Reason,
				Success:    false,
				Error:      err.Error(),
				Duration:   now().Sub(callStart),
			})
			return err
		}
		// Cloudflare already has a live rule for this IP (error code 10009,
		// "firewallaccessrules.api.duplicate_of_existing"). This is not a
		// failure: the desired end state (IP is blocked at Cloudflare) is
		// already true. Treat it as idempotent success so:
		//   - the caller's `if ExecuteBan(...) == nil { RecordBan(ip) }`
		//     pattern still marks the IP as banned in the dedup store
		//     (see daemon_runtime.go, nginxerrors/service.go), preventing
		//     the retry-storm where the same IP is re-attempted every poll
		//     cycle forever.
		//   - we backfill a banlifecycle.Entry for IPs that were banned
		//     before the lifecycle feature existed, or whose entry was
		//     lost (e.g. across a restart before this code path existed).
		//
		// We look up the existing rule's ID (and, when available, its real
		// creation time) via ListIPAccessRulesByNotePrefix rather than
		// ListIPAccessRulesByTag: the tag embeds the freshly-computed
		// exp=<RFC3339> timestamp from THIS call, which will never equal
		// the older rule's note (computed at its own original creation
		// time), so an exact-match tag lookup would never find it.
		if e.logger != nil {
			e.logger.Info("autoban: CF rule already exists for IP, treating as idempotent success",
				"ip", decision.IP, "reason", decision.Reason, "error", err)
		}
		existing, found := e.lookupExistingRule(ctx, decision.IP)
		if !found && e.logger != nil {
			e.logger.Warn("autoban: could not resolve existing CF rule ID for duplicate ban; lifecycle entry will be backfilled with empty rule_id",
				"ip", decision.IP)
		}
		if found {
			id = existing.ID
		}
		// Prefer the existing rule's real creation time when we can resolve
		// it, so recidive-level escalation timing isn't reset by a restart
		// or a re-attempted ban. If we can't resolve it (lookup failed, or
		// the rule predates this code / wasn't created by cf-sync), "now"
		// is used as a documented fallback below; this means the computed
		// expires_at for a backfilled entry may not reflect when the IP
		// was actually first blocked.
		if found && !existing.CreatedOn.IsZero() {
			createdAt = existing.CreatedOn
			expiresAt = createdAt.Add(duration)
		}
	} else if e.logger != nil {
		e.logger.Info("autoban: CF ban applied", "ip", decision.IP, "reason", decision.Reason, "rule_id", id,
			"recidive_level", recidiveLevel, "duration", duration, "expires_at", expiresAt)
	}

	if e.lifecycleStore != nil {
		entry := banlifecycle.Entry{
			IP:            decision.IP,
			Source:        "autoban_" + decision.Reason,
			Reason:        decision.Reason,
			Confidence:    decision.Confidence,
			CreatedAt:     createdAt,
			ExpiresAt:     expiresAt,
			Duration:      duration,
			RuleID:        id,
			RecidiveLevel: recidiveLevel,
			Status:        banlifecycle.StatusActive,
		}
		if err := e.lifecycleStore.Upsert(ctx, entry); err != nil && e.logger != nil {
			e.logger.Warn("autoban: ban lifecycle store upsert failed", "ip", decision.IP, "error", err)
		}
	}
	e.recordEnforcementEvent(ctx, enforcementlog.Event{
		OccurredAt: createdAt,
		Action:     enforcementlog.ActionBanApplied,
		IP:         decision.IP,
		Reason:     decision.Reason,
		RuleID:     id,
		Success:    true,
		Duration:   now().Sub(callStart),
	})
	return nil
}

// cfDuplicateRuleErrorSlug is the stable Cloudflare API error slug returned
// alongside numeric code 10009 when AddIPAccessRule targets an IP that
// already has a live access rule. The numeric code is not preserved as a
// structured field by this point: cftransport.MutateAndDecode formats the
// whole []models.ResponseError slice into the error message via %v (see
// internal/cloudflare/transport/transport.go), so the code is only
// recoverable here as a substring of err.Error(). The slug
// ("firewallaccessrules.api.duplicate_of_existing") is stable across CF API
// versions and is what the production journal evidence for this bug shows,
// so we match on it directly rather than parsing out the numeric code.
const cfDuplicateRuleErrorSlug = "duplicate_of_existing"

// isCFDuplicateRuleError reports whether err represents Cloudflare's
// "firewallaccessrules.api.duplicate_of_existing" (code 10009) response,
// returned when an access rule already exists for the requested IP.
func isCFDuplicateRuleError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), cfDuplicateRuleErrorSlug)
}

// lookupExistingRule resolves the pre-existing Cloudflare access rule for ip,
// used to backfill a banlifecycle.Entry (rule ID and, when available, real
// creation time) when AddIPAccessRule reports a duplicate instead of
// creating a new rule. Returns ok=false if the client is unavailable, the
// lookup fails, or no matching rule is found (e.g. the existing rule wasn't
// created by cf-sync's autoban path and so doesn't carry the
// "cf-sync:autoban:" note prefix). It finds the rule among all rules
// whose notes start with the "cf-sync:autoban:" prefix. It cannot use
// ListIPAccessRulesByTag because that method requires an exact notes match
// and the notes tag embeds an exp=<RFC3339> timestamp computed fresh on
// every ExecuteBan call, which will never equal an existing rule's
// (differently-timestamped) note.
func (e *cfBanExecutor) lookupExistingRule(ctx context.Context, ip string) (models.IPAccessRule, bool) {
	if e == nil || e.client == nil {
		return models.IPAccessRule{}, false
	}
	rules, err := e.client.ListIPAccessRulesByNotePrefix(ctx, e.zoneID, "cf-sync:autoban:")
	if err != nil {
		if e.logger != nil {
			e.logger.Warn("autoban: lookup of existing CF rule by note prefix failed", "ip", ip, "error", err)
		}
		return models.IPAccessRule{}, false
	}
	want := normalizeIPForCompare(ip)
	for _, r := range rules {
		if normalizeIPForCompare(r.Configuration.Value) == want {
			return r, true
		}
	}
	return models.IPAccessRule{}, false
}

// normalizeIPForCompare normalizes a plain IP string for comparison.
// ListIPAccessRulesByNotePrefix returns raw configuration values (unlike
// ListIPAccessRulesByTag, it does not net.ParseIP-normalize them), so both
// sides of any comparison must be normalized the same way here.
func normalizeIPForCompare(value string) string {
	if parsed := net.ParseIP(value); parsed != nil {
		return parsed.String()
	}
	return value
}

// LastBanDuration returns the Duration recorded in this IP's most recent
// banlifecycle.Entry — i.e. the actual ban duration ExecuteBan just applied
// (or, for an already-existing rule, the duration of whatever ban is
// currently active for it). Returns (0, false) when there is no lifecycle
// store wired, no entry exists yet, or the lookup fails; callers must treat
// that as "duration unknown" and fall back to a safe default rather than
// assuming a short duration.
//
// This is intentionally a separate read-after-write step rather than having
// ExecuteBan return the duration directly: ExecuteBan's signature
// (ctx, decision) error is also being modified by a separate in-flight PR
// (#78, fix/cf-ban-duplicate-idempotent) that rewrites large parts of its
// body; adding a second return value here would conflict with that PR's
// diff on nearly every line. Reading the just-persisted entry back out is
// equivalent (it reflects whatever duration was actually computed and
// stored, including any future backfill logic like #78's duplicate-rule
// handling) without touching ExecuteBan's signature or body at all.
func (e *cfBanExecutor) LastBanDuration(ctx context.Context, ip string) (time.Duration, bool) {
	if e == nil || e.lifecycleStore == nil {
		return 0, false
	}
	entry, ok, err := e.lifecycleStore.Get(ctx, ip)
	if err != nil || !ok {
		return 0, false
	}
	return entry.Duration, true
}

// banDurationLookup is satisfied by *cfBanExecutor (and any future
// BanExecutor implementation) that can report the actual duration applied
// to a specific IP's most recent ban. It is intentionally a small,
// additive interface — NOT a method added to autoban.BanExecutor itself —
// so existing BanExecutor implementations (including test fakes) keep
// compiling unchanged; callers type-assert for it and fall back to the
// fixed-TTL dedup path when an executor doesn't support it.
type banDurationLookup interface {
	LastBanDuration(ctx context.Context, ip string) (time.Duration, bool)
}

// recordBanAfterExecute marks ip as banned in evalr's dedup guard using the
// real ban duration that was just applied, when banExec exposes one via
// banDurationLookup (true for *cfBanExecutor). Falls back to the fixed
// legacy BanDedupTTL via RecordBan when the executor doesn't support the
// lookup, or the lookup fails — this can only make the dedup guard hold
// longer than (never shorter than) the real ban, which is the safe
// direction per the "never relax a guard while a CF rule is still active"
// requirement.
func recordBanAfterExecute(ctx context.Context, evalr *autoban.Evaluator, banExec autoban.BanExecutor, ip string) {
	if evalr == nil {
		return
	}
	if lookup, ok := banExec.(banDurationLookup); ok {
		if d, found := lookup.LastBanDuration(ctx, ip); found && d > 0 {
			evalr.RecordBanWithDuration(ip, d)
			return
		}
	}
	evalr.RecordBan(ip)
}
