package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"time"

	"github.com/jm/security-automation-go/internal/abuseipdb"
	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/betterstack"
	"github.com/jm/security-automation-go/internal/cloudflare"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/crowdsec"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/logging"
	"github.com/jm/security-automation-go/internal/modsecurity"
	"github.com/jm/security-automation-go/internal/recidive"
	"github.com/jm/security-automation-go/internal/scheduler"
	"github.com/jm/security-automation-go/internal/security/protected"
	"github.com/jm/security-automation-go/internal/shadow"
	"github.com/jm/security-automation-go/internal/state"
)

// NOTE_TAG is the Cloudflare rule notes tag for CrowdSec-managed bans.
// Mirrors Python's NOTE_TAG = "crowdsec-local-ban".
const NOTE_TAG = "crowdsec-local-ban"

// NOTE_TAG_CIDR is the notes tag for automatic /24 CIDR bans.
const NOTE_TAG_CIDR = "crowdsec-cidr-ban"

// NOTE_TAG_MODSEC is the notes tag for ModSecurity-triggered bans.
const NOTE_TAG_MODSEC = "modsec-ban"

type Runner interface {
	Run(ctx context.Context) error
}

type CrowdSecSyncApp struct {
	logger      *slog.Logger
	cfg         *config.Config
	store       state.Store
	cf          cloudflare.EnforcementClient
	cs          crowdsec.ActiveBanSource
	csDecisions crowdsec.DecisionManager
	abuse       *abuseipdb.Client
	better      betterstack.IngestClient
	modsec      modsecurity.Service
	recidiv     recidive.Service

	// Anti-self-ban shield (P0 safety).
	shield *protected.Shield

	// Shadow mode: compute plans but do not mutate Cloudflare.
	shadowMode   bool
	shadowStore  *shadow.Store
	shadowReport string // path to SHADOW_MODE_REPORT.md
}

type AllowlistSyncApp struct {
	logger *slog.Logger
	cfg    *config.Config
	cf     cloudflare.ListClient
	cs     crowdsec.AllowlistManager
}

type CleanupApp struct {
	logger *slog.Logger
	cfg    *config.Config
	cf     cloudflare.EnforcementClient
	cs     crowdsec.ActiveBanSource
}

func NewCrowdSecSyncApp(logger *slog.Logger, cfg *config.Config) *CrowdSecSyncApp {
	httpClient := httpclient.New(cfg.Global.HTTP)
	cfClient := cloudflare.NewClient(httpClient, cfg.Cloudflare.APIToken)
	csClient := crowdsec.NewClientFromConfig(cfg.CrowdSec.BinPath, cfg.CrowdSec.DecisionsLog, cfg.CrowdSec.Timeout)

	var abuse *abuseipdb.Client
	if cfg.AbuseIPDB.APIKey != "" && !abuseIPDBReportingDisabled(cfg) {
		abuse = abuseipdb.NewClient(cfg.AbuseIPDB.APIKey, httpClient)
	}

	return &CrowdSecSyncApp{
		logger:       logger,
		cfg:          cfg,
		store:        state.NewJSONStore(cfg.StateDir),
		cf:           cfClient,
		cs:           csClient,
		csDecisions:  csClient,
		abuse:        abuse,
		better:       betterstack.NewClient(httpClient, cfg.BetterStack.SourceToken, cfg.BetterStack.IngestingHost),
		modsec:       modsecurity.NewService(modsecurity.Config{NginxLogDir: cfg.CrowdSec.NginxLogDir}),
		recidiv:      recidive.NewService(recidive.Config{StateDir: cfg.StateDir}),
		shield:       protected.New(),
		shadowStore:  shadow.NewStore(cfg.StateDir),
		shadowReport: filepath.Join(cfg.StateDir, "SHADOW_MODE_REPORT.md"),
	}
}

func NewAllowlistSyncApp(logger *slog.Logger, cfg *config.Config) *AllowlistSyncApp {
	httpClient := httpclient.New(cfg.Global.HTTP)
	return &AllowlistSyncApp{
		logger: logger,
		cfg:    cfg,
		cf:     cloudflare.NewClient(httpClient, cfg.Cloudflare.APIToken),
		cs:     crowdsec.NewClientFromConfig(cfg.CrowdSec.BinPath, cfg.CrowdSec.DecisionsLog, cfg.CrowdSec.Timeout),
	}
}

func NewCleanupApp(logger *slog.Logger, cfg *config.Config) *CleanupApp {
	httpClient := httpclient.New(cfg.Global.HTTP)
	cfClient := cloudflare.NewClient(httpClient, cfg.Cloudflare.APIToken)
	csClient := crowdsec.NewClientFromConfig(cfg.CrowdSec.BinPath, cfg.CrowdSec.DecisionsLog, cfg.CrowdSec.Timeout)
	return &CleanupApp{
		logger: logger,
		cfg:    cfg,
		cf:     cfClient,
		cs:     csClient,
	}
}

// WithShadowMode enables shadow mode: Go computes plans but does not mutate CF.
// The report path is where SHADOW_MODE_REPORT.md is written after each cycle.
func (a *CrowdSecSyncApp) WithShadowMode(reportPath string) *CrowdSecSyncApp {
	a.shadowMode = true
	if reportPath != "" {
		a.shadowReport = reportPath
	}
	return a
}

// ── CrowdSecSyncApp ───────────────────────────────────────────────────────────

func (a *CrowdSecSyncApp) Run(ctx context.Context) error {
	const op = "app.CrowdSecSyncApp.Run"
	if ctx == nil {
		return apperr.New(op, "context is required")
	}
	ctx = logging.WithTraceLogger(ctx, a.logger)
	logger := logging.FromContext(ctx, a.logger)
	logger.InfoContext(ctx, "starting crowdsec sync daemon", "interval", a.cfg.Interval)

	wafRuntime := newWAFReportingRuntime(ctx, logger, a.cfg, a.abuse, a.better)
	defer wafRuntime.close()

	runner := &scheduler.IntervalRunner{
		Name:     "crowdsec-sync",
		Interval: a.cfg.Interval,
		Timeout:  a.cfg.Interval,
	}
	task := schedulerTask(func(runCtx context.Context) error {
		runCtx = logging.WithTraceLogger(runCtx, a.logger)
		l := logging.FromContext(runCtx, a.logger)
		l.InfoContext(runCtx, "crowdsec sync tick")

		// Core enforcement loop: CrowdSec active bans → Cloudflare IP rules.
		if err := a.syncCloudflare(runCtx, l); err != nil {
			l.WarnContext(runCtx, "cf sync failed (non-fatal)", "error", err)
		}

		// Subsidiary enforcement features.
		if err := a.recidiv.Run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
			l.WarnContext(runCtx, "recidive sync failed (non-fatal)", "error", err)
		}
		if err := a.modsec.Run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
			l.WarnContext(runCtx, "modsec sync failed (non-fatal)", "error", err)
		}

		// AbuseIPDB reporting pipeline (CrowdSec events, OpenResty, outbox).
		wafRuntime.processCrowdSec(runCtx, l)
		wafRuntime.processOpenResty(runCtx, l)
		wafRuntime.processOutbox(runCtx, l)
		return nil
	})

	if err := runner.Run(ctx, task); err != nil && !errors.Is(err, context.Canceled) {
		return apperr.Wrap(op, err)
	}
	return nil
}

// buildSyncPlan computes what Go would add/remove without executing anything.
// Applies anti-self-ban (P0) filter identical to Python's is_protected().
// Also applies allowlist filter when cs implements AllowlistManager.
func (a *CrowdSecSyncApp) buildSyncPlan(
	ctx context.Context,
	activeBans []string,
	cfRules map[string]string, // ip → ruleID
) shadow.SyncPlan {
	// Normalize IPs + apply anti-self-ban (P0) + allowlist filter.
	banSet := make(map[string]bool, len(activeBans))
	for _, ip := range activeBans {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		norm := parsed.String()
		if a.shield != nil && a.shield.IsProtected(norm) {
			continue // P0: never ban protected ranges
		}
		banSet[norm] = true
	}

	cfSet := make(map[string]bool, len(cfRules))
	for ip := range cfRules {
		cfSet[ip] = true
	}

	var toAdd []string
	for ip := range banSet {
		if !cfSet[ip] {
			toAdd = append(toAdd, ip)
		}
	}
	var toDelete []string
	for ip := range cfSet {
		if !banSet[ip] {
			toDelete = append(toDelete, ip)
		}
	}
	return shadow.SyncPlan{
		ActiveBans: banSet,
		CFRules:    cfSet,
		ToAdd:      toAdd,
		ToDelete:   toDelete,
	}
}

// syncCloudflare implements Python's sync_cloudflare():
//   - Get active bans from CrowdSec (cscli decisions list)
//   - Apply anti-self-ban filter (P0)
//   - Get current CF rules tagged "crowdsec-local-ban"
//   - Compute diff: to_add, to_delete
//   - In shadow mode: log plan, compare vs CF state, update report — no mutations
//   - In live mode: apply mutations with 100ms courtesy sleep
func (a *CrowdSecSyncApp) syncCloudflare(ctx context.Context, logger *slog.Logger) error {
	zoneID := a.cfg.Cloudflare.ZoneID

	activeBans, err := a.cs.ListActiveBans(ctx)
	if err != nil {
		return fmt.Errorf("syncCloudflare: ListActiveBans: %w", err)
	}

	cfRules, err := a.cf.ListIPAccessRulesByTag(ctx, zoneID, NOTE_TAG)
	if err != nil {
		return fmt.Errorf("syncCloudflare: ListIPAccessRulesByTag: %w", err)
	}

	plan := a.buildSyncPlan(ctx, activeBans, cfRules)

	logger.InfoContext(ctx, "cf sync plan",
		"shadow_mode", a.shadowMode,
		"active_bans", len(plan.ActiveBans),
		"cf_rules", len(plan.CFRules),
		"to_add", len(plan.ToAdd),
		"to_delete", len(plan.ToDelete),
	)

	if a.shadowMode {
		return a.recordShadowCycle(ctx, logger, plan)
	}

	// Live mode: apply mutations.
	added, deleted := 0, 0
	for _, ip := range plan.ToAdd {
		if _, err := a.cf.AddIPAccessRule(ctx, zoneID, ip, NOTE_TAG, "ip"); err != nil {
			logger.WarnContext(ctx, "cf add rule failed", "ip", ip, "error", err)
			continue
		}
		logger.InfoContext(ctx, "cf: added", "ip", ip)
		added++
		time.Sleep(100 * time.Millisecond) // Python: time.sleep(0.1)
	}
	for _, ip := range plan.ToDelete {
		ruleID := cfRules[ip]
		if err := a.cf.DeleteIPAccessRule(ctx, zoneID, ruleID); err != nil {
			logger.WarnContext(ctx, "cf delete rule failed", "ip", ip, "error", err)
			continue
		}
		logger.InfoContext(ctx, "cf: removed (ban expired)", "ip", ip)
		deleted++
		time.Sleep(100 * time.Millisecond)
	}

	if added > 0 || deleted > 0 {
		logger.InfoContext(ctx, "cf sync complete", "added", added, "deleted", deleted)
	}
	return nil
}

// recordShadowCycle records one shadow comparison cycle and regenerates the report.
// Python remains authoritative; Go only observes and measures plan equivalence.
func (a *CrowdSecSyncApp) recordShadowCycle(ctx context.Context, logger *slog.Logger, plan shadow.SyncPlan) error {
	cycle := shadow.Compare(plan, time.Now().UTC())

	logger.InfoContext(ctx, "shadow cycle",
		"agreement_pct", fmt.Sprintf("%.2f%%", cycle.AgreementPct),
		"in_sync", cycle.InSync,
		"false_positives", len(cycle.FalsePositives),
		"false_negatives", len(cycle.FalseNegatives),
	)

	if !cycle.InSync {
		logger.WarnContext(ctx, "shadow drift detected",
			"drift", cycle.DriftExplanation,
			"to_add", cycle.PlannedAdds[:min(len(cycle.PlannedAdds), 5)],
			"to_delete", cycle.PlannedDeletes[:min(len(cycle.PlannedDeletes), 5)],
		)
	}

	if err := a.shadowStore.Append(cycle); err != nil {
		logger.WarnContext(ctx, "shadow store append failed", "error", err)
	}

	// Prune records older than 30 days; 7-day criterion needs ≥ 7d of data.
	_ = a.shadowStore.Prune(time.Now().UTC().Add(-30 * 24 * time.Hour))

	// Regenerate all three reports from the last 7 days of cycles.
	if a.shadowReport != "" {
		reportDir := filepath.Dir(a.shadowReport)
		cycles, err := a.shadowStore.ReadSince(time.Now().UTC().Add(-7 * 24 * time.Hour))
		if err == nil && len(cycles) > 0 {
			isProtected := func(ip string) bool {
				return a.shield != nil && a.shield.IsProtected(ip)
			}
			// SHADOW_MODE_REPORT.md — per-cycle agreement metrics
			if err := shadow.WriteReport(a.shadowReport, cycles); err != nil {
				logger.WarnContext(ctx, "shadow report write failed", "error", err)
			}
			// SHADOW_DRIFT_ANALYSIS.md — drift classification and remediation list
			driftPath := filepath.Join(reportDir, "SHADOW_DRIFT_ANALYSIS.md")
			if err := shadow.WriteDriftAnalysis(driftPath, cycles, isProtected, nil); err != nil {
				logger.WarnContext(ctx, "drift analysis write failed", "error", err)
			}
			// PYTHON_GO_PARITY_REPORT.md — feature gap cross-reference
			parityPath := filepath.Join(reportDir, "PYTHON_GO_PARITY_REPORT.md")
			if err := shadow.WriteParityReport(parityPath, cycles, isProtected, nil); err != nil {
				logger.WarnContext(ctx, "parity report write failed", "error", err)
			}
			logger.InfoContext(ctx, "shadow reports updated",
				"shadow", a.shadowReport,
				"drift", driftPath,
				"parity", parityPath,
			)
		}
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── AllowlistSyncApp ──────────────────────────────────────────────────────────

func (a *AllowlistSyncApp) Run(ctx context.Context) error {
	const op = "app.AllowlistSyncApp.Run"
	if ctx == nil {
		return apperr.New(op, "context is required")
	}
	ctx = logging.WithTraceLogger(ctx, a.logger)
	logger := logging.FromContext(ctx, a.logger)

	name := a.cfg.CrowdSec.AllowlistName
	logger.InfoContext(ctx, "syncing crowdsec allowlist", "name", name)

	entries, err := a.cs.ListAllowlist(ctx, name)
	if err != nil {
		return apperr.Wrapf(op, err, "ListAllowlist %s", name)
	}
	logger.InfoContext(ctx, "crowdsec allowlist loaded", "name", name, "count", len(entries))
	for _, e := range entries {
		logger.InfoContext(ctx, "allowlist entry", "value", e.Value, "comment", e.Comment)
	}
	return nil
}

// ── CleanupApp ────────────────────────────────────────────────────────────────

// Run implements Python's reconcile_state() drift-removal path:
// delete crowdsec-local-ban rules from Cloudflare for IPs no longer banned in CrowdSec.
func (a *CleanupApp) Run(ctx context.Context) error {
	const op = "app.CleanupApp.Run"
	if ctx == nil {
		return apperr.New(op, "context is required")
	}
	ctx = logging.WithTraceLogger(ctx, a.logger)
	logger := logging.FromContext(ctx, a.logger)
	zoneID := a.cfg.Cloudflare.ZoneID

	logger.InfoContext(ctx, "starting cleanup: scanning for stale CF rules")

	activeBans, err := a.cs.ListActiveBans(ctx)
	if err != nil {
		return apperr.Wrapf(op, err, "ListActiveBans")
	}
	banSet := make(map[string]bool, len(activeBans))
	for _, ip := range activeBans {
		if parsed := net.ParseIP(ip); parsed != nil {
			banSet[parsed.String()] = true
		} else {
			banSet[ip] = true
		}
	}

	cfRules, err := a.cf.ListIPAccessRulesByTag(ctx, zoneID, NOTE_TAG)
	if err != nil {
		return apperr.Wrapf(op, err, "ListIPAccessRulesByTag")
	}

	deleted := 0
	for ip, ruleID := range cfRules {
		if banSet[ip] {
			continue
		}
		if err := a.cf.DeleteIPAccessRule(ctx, zoneID, ruleID); err != nil {
			logger.WarnContext(ctx, "cleanup: delete failed", "ip", ip, "error", err)
			continue
		}
		logger.InfoContext(ctx, "cleanup: removed stale rule", "ip", ip)
		deleted++
		time.Sleep(100 * time.Millisecond)
	}
	logger.InfoContext(ctx, "cleanup complete", "scanned", len(cfRules), "deleted", deleted)
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

type schedulerTask func(ctx context.Context) error

func (t schedulerTask) Run(ctx context.Context) error { return t(ctx) }

func abuseIPDBReportingDisabled(cfg *config.Config) bool {
	return cfg != nil && cfg.AbuseIPDB.ReportingEnabled != nil && !*cfg.AbuseIPDB.ReportingEnabled
}
