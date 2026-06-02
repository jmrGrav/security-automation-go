package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"time"

	cloudflareevent "github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/logging"
	"github.com/jm/security-automation-go/internal/scheduler"
	"github.com/jm/security-automation-go/internal/shadow"
)

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

	// WAF replay: optional. Active when CF source and AbuseIPDB are both available
	// and SQLite cursor store is initialised. Suppressed in shadow mode.
	if !a.shadowMode && wafRuntime != nil && wafRuntime.cursorStore != nil && wafRuntime.service != nil {
		if wafSource, ok := a.cf.(cloudflareevent.Source); ok {
			wafSvc := cloudflareevent.NewService(wafSource, wafRuntime.service)
			wafRuntime.startWAFReplay(ctx, logger, wafSvc, wafRuntime.cursorStore,
				a.cfg.Cloudflare.ZoneID, a.cfg.Interval)
			logger.InfoContext(ctx, "cloudflare waf replay started", "interval", a.cfg.Interval)
		}
	}

	runner := &scheduler.IntervalRunner{
		Name:     "crowdsec-sync",
		Interval: a.cfg.Interval,
		Timeout:  a.cfg.Interval,
	}
	task := schedulerTask(func(runCtx context.Context) error {
		runCtx = logging.WithTraceLogger(runCtx, a.logger)
		l := logging.FromContext(runCtx, a.logger)
		l.InfoContext(runCtx, "crowdsec sync tick")

		if err := a.syncCloudflare(runCtx, l); err != nil {
			l.WarnContext(runCtx, "cf sync failed (non-fatal)", "error", err)
		}

		// Subsidiary enforcement features.
		if !a.shadowMode {
			if err := a.cidr.Run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
				l.WarnContext(runCtx, "cidr ban sync failed (non-fatal)", "error", err)
			}
		}
		if !a.shadowMode {
			if err := a.recidiv.Run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
				l.WarnContext(runCtx, "recidive sync failed (non-fatal)", "error", err)
			}
		}

		wafRuntime.processCrowdSec(runCtx, l)
		wafRuntime.processOpenResty(runCtx, l)
		wafRuntime.processOutbox(runCtx, l)

		if !a.shadowMode {
			a.pushLuaState(runCtx, l)
		}
		return nil
	})

	if err := runner.Run(ctx, task); err != nil && !errors.Is(err, context.Canceled) {
		return apperr.Wrap(op, err)
	}
	return nil
}

func (a *CrowdSecSyncApp) buildSyncPlan(
	ctx context.Context,
	activeBans []string,
	cfRules map[string]string,
) shadow.SyncPlan {
	allowlist := a.fetchAllowlist(ctx)

	banSet := make(map[string]bool, len(activeBans))
	for _, ip := range activeBans {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		norm := parsed.String()
		if a.shield != nil && a.shield.IsProtected(norm) {
			continue
		}
		if allowlist.contains(norm) {
			a.logger.DebugContext(ctx, "allowlist: skip ip", "ip", norm)
			continue
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

	added, deleted := 0, 0
	for _, ip := range plan.ToAdd {
		if _, err := a.cf.AddIPAccessRule(ctx, zoneID, ip, NOTE_TAG, "ip"); err != nil {
			logger.WarnContext(ctx, "cf add rule failed", "ip", ip, "error", err)
			continue
		}
		logger.InfoContext(ctx, "cf: added", "ip", ip)
		added++
		if err := sleepWithContext(ctx, 100*time.Millisecond); err != nil {
			return err
		}
	}
	for _, ip := range plan.ToDelete {
		ruleID := cfRules[ip]
		if err := a.cf.DeleteIPAccessRule(ctx, zoneID, ruleID); err != nil {
			logger.WarnContext(ctx, "cf delete rule failed", "ip", ip, "error", err)
			continue
		}
		logger.InfoContext(ctx, "cf: removed (ban expired)", "ip", ip)
		deleted++
		if err := sleepWithContext(ctx, 100*time.Millisecond); err != nil {
			return err
		}
	}

	if added > 0 || deleted > 0 {
		logger.InfoContext(ctx, "cf sync complete", "added", added, "deleted", deleted)
	}
	return nil
}

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

	_ = a.shadowStore.Prune(time.Now().UTC().Add(-30 * 24 * time.Hour))

	if a.shadowReport != "" {
		reportDir := filepath.Dir(a.shadowReport)
		cycles, err := a.shadowStore.ReadSince(time.Now().UTC().Add(-7 * 24 * time.Hour))
		if err == nil && len(cycles) > 0 {
			isProtected := func(ip string) bool {
				return a.shield != nil && a.shield.IsProtected(ip)
			}
			allowlist := a.fetchAllowlist(ctx)
			allowlistMap := allowlist.asMap()

			if err := shadow.WriteReport(a.shadowReport, cycles); err != nil {
				logger.WarnContext(ctx, "shadow report write failed", "error", err)
			}
			driftPath := filepath.Join(reportDir, "SHADOW_DRIFT_ANALYSIS.md")
			if err := shadow.WriteDriftAnalysis(driftPath, cycles, isProtected, allowlistMap); err != nil {
				logger.WarnContext(ctx, "drift analysis write failed", "error", err)
			}
			parityPath := filepath.Join(reportDir, "PYTHON_GO_PARITY_REPORT.md")
			if err := shadow.WriteParityReport(parityPath, cycles, isProtected, allowlistMap); err != nil {
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

	plan := buildCleanupPlan(banSet, cfRules)
	if a.dryRun {
		logger.InfoContext(ctx, "cleanup dry-run summary",
			"scanned", len(cfRules),
			"kept", len(plan.kept),
			"would_delete", len(plan.stale),
			"delete_reason", "not in active CrowdSec bans",
		)
		for _, item := range plan.stale {
			logger.InfoContext(ctx, "cleanup dry-run stale rule", "ip", item.IP, "rule_id", item.RuleID, "reason", item.Reason)
		}
		logger.InfoContext(ctx, "cleanup dry-run complete", "scanned", len(cfRules), "kept", len(plan.kept), "would_delete", len(plan.stale))
		return nil
	}

	deleted := 0
	var deleteErrs []error
	for _, item := range plan.stale {
		if err := a.cf.DeleteIPAccessRule(ctx, zoneID, item.RuleID); err != nil {
			logger.WarnContext(ctx, "cleanup: delete failed", "ip", item.IP, "error", err)
			deleteErrs = append(deleteErrs, fmt.Errorf("delete %s: %w", item.IP, err))
			continue
		}
		logger.InfoContext(ctx, "cleanup: removed stale rule", "ip", item.IP)
		deleted++
		if err := sleepWithContext(ctx, 100*time.Millisecond); err != nil {
			return apperr.Wrap(op, err)
		}
	}
	logger.InfoContext(ctx, "cleanup complete", "scanned", len(cfRules), "deleted", deleted)
	if len(deleteErrs) > 0 {
		return apperr.Wrap(op, errors.Join(deleteErrs...))
	}
	return nil
}

type cleanupCandidate struct {
	IP     string
	RuleID string
	Reason string
}

type cleanupPlan struct {
	kept  []cleanupCandidate
	stale []cleanupCandidate
}

func buildCleanupPlan(activeBans map[string]bool, cfRules map[string]string) cleanupPlan {
	plan := cleanupPlan{
		kept:  make([]cleanupCandidate, 0, len(cfRules)),
		stale: make([]cleanupCandidate, 0, len(cfRules)),
	}
	for ip, ruleID := range cfRules {
		item := cleanupCandidate{IP: ip, RuleID: ruleID, Reason: "not in active CrowdSec bans"}
		if activeBans[ip] {
			plan.kept = append(plan.kept, item)
			continue
		}
		plan.stale = append(plan.stale, item)
	}
	return plan
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type schedulerTask func(ctx context.Context) error

func (t schedulerTask) Run(ctx context.Context) error { return t(ctx) }

func abuseIPDBReportingDisabled(cfg *config.Config) bool {
	return cfg != nil && cfg.AbuseIPDB.ReportingEnabled != nil && !*cfg.AbuseIPDB.ReportingEnabled
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
