package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	cloudflareevent "github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/logging"
	"github.com/jm/security-automation-go/internal/scheduler"
	"github.com/jm/security-automation-go/internal/trustednetworks"
)

func (a *CrowdSecSyncApp) Run(ctx context.Context) error {
	const op = "app.CrowdSecSyncApp.Run"
	if ctx == nil {
		return apperr.New(op, "context is required")
	}
	ctx = logging.WithTraceLogger(ctx, a.logger)
	logger := logging.FromContext(ctx, a.logger)
	logger.InfoContext(ctx, "starting crowdsec sync daemon", "interval", a.cfg.Interval)

	if a.poller != nil {
		go func() {
			if err := a.poller.Run(ctx); err != nil {
				logger.ErrorContext(ctx, "crowdsec poller stopped", "error", err)
			}
		}()
		logger.InfoContext(ctx, "crowdsec poller started",
			"interval", a.cfg.CrowdSec.PollerInterval,
			"lapi_url", a.cfg.CrowdSec.PollerLAPIURL,
		)
	}

	wafRuntime := newWAFReportingRuntime(ctx, logger, a.cfg, a.abuse, a.better)
	defer wafRuntime.close()

	// WAF replay: optional. Active when CF source and AbuseIPDB are both available
	// and SQLite cursor store is initialised.
	if wafRuntime != nil && wafRuntime.cursorStore != nil && wafRuntime.service != nil {
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
		if err := a.cidr.Run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
			l.WarnContext(runCtx, "cidr ban sync failed (non-fatal)", "error", err)
		}
		if err := a.recidiv.Run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
			l.WarnContext(runCtx, "recidive sync failed (non-fatal)", "error", err)
		}

		wafRuntime.processCrowdSec(runCtx, l)
		wafRuntime.processOpenResty(runCtx, l)
		wafRuntime.processOutbox(runCtx, l)

		a.pushLuaState(runCtx, l)
		return nil
	})

	if err := runner.Run(ctx, task); err != nil && !errors.Is(err, context.Canceled) {
		return apperr.Wrap(op, err)
	}
	return nil
}

// syncPlan is the set-difference between CrowdSec's currently active bans
// and Cloudflare's currently active IP access rules: ToAdd are bans missing
// a CF rule, ToDelete are CF rules whose ban has expired/lifted.
type syncPlan struct {
	ActiveBans map[string]bool
	CFRules    map[string]bool
	ToAdd      []string
	ToDelete   []string
}

func (a *CrowdSecSyncApp) buildSyncPlan(
	ctx context.Context,
	activeBans []string,
	cfRules map[string]string,
) syncPlan {
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
	return syncPlan{
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
		"active_bans", len(plan.ActiveBans),
		"cf_rules", len(plan.CFRules),
		"to_add", len(plan.ToAdd),
		"to_delete", len(plan.ToDelete),
	)

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

// Run performs one CrowdSec-spoke reconcile pass: load the trusted-networks
// registry, push additively to the CrowdSec allowlist (enforce mode only;
// shadow mode detects but never mutates), detect drift, and persist the
// result to statusStore. This is the only code path in the whole codebase
// permitted to invoke `cscli allowlists inspect/add/remove` — see
// internal/crowdsec/client_boundary_test.go's
// TestCrowdSecWriteCommandsOnlyInClient for the static guard and
// cmd/cf-sync's daemon-side guard asserting the daemon never wires the
// CrowdSec spoke itself.
//
// Run always reports its outcome to statusStore (success or failure) so a
// stale "never ran" status is never confused with "ran and failed" — both
// the daemon and UI must be able to tell the difference (e.g. permission
// denied reading local_api_credentials.yaml vs. helper timer disabled).
func (a *AllowlistSyncApp) Run(ctx context.Context) error {
	const op = "app.AllowlistSyncApp.Run"
	if ctx == nil {
		return apperr.New(op, "context is required")
	}
	ctx = logging.WithTraceLogger(ctx, a.logger)
	logger := logging.FromContext(ctx, a.logger)

	if a.reg == nil || a.reg.CrowdSecAllowlistName == "" {
		logger.InfoContext(ctx, "crowdsec allowlist sync: disabled (no allowlist name configured)")
		return nil
	}
	name := a.reg.CrowdSecAllowlistName
	logger.InfoContext(ctx, "syncing crowdsec allowlist", "name", name, "mode", a.reg.EffectiveMode())

	report, syncErr := a.reg.Sync(ctx)
	status := crowdSecStatusFromReport(name, report)

	if syncErr != nil {
		status.LastError = syncErr.Error()
		logger.ErrorContext(ctx, "crowdsec allowlist sync: registry load failed", "name", name, "error", syncErr)
	} else if len(report.CrowdSec.Errors) > 0 {
		status.LastError = report.CrowdSec.Errors[0]
		logger.WarnContext(ctx, "crowdsec allowlist sync: spoke reported errors", "name", name, "errors", report.CrowdSec.Errors)
		// A failed cscli call (e.g. permission denied reading
		// local_api_credentials.yaml) must fail this run closed, not just
		// be logged — the timer's exit code is the only out-of-band signal
		// an operator gets if the persisted status itself can't be read.
		syncErr = fmt.Errorf("crowdsec spoke: %s", report.CrowdSec.Errors[0])
	} else {
		logger.InfoContext(ctx, "crowdsec allowlist sync complete",
			"name", name,
			"desired_count", status.DesiredCount,
			"current_count", status.CurrentCount,
			"drift_count", status.DriftCount,
		)
	}

	if a.statusStore != nil {
		if err := a.statusStore.PutCrowdSecAllowlistStatus(ctx, status); err != nil {
			logger.ErrorContext(ctx, "crowdsec allowlist sync: failed to persist status", "error", err)
			if syncErr == nil {
				syncErr = err
			}
		}
	}

	if syncErr != nil {
		return apperr.Wrapf(op, syncErr, "sync %s", name)
	}
	return nil
}

// crowdSecStatusFromReport derives a persisted status snapshot from one
// Registry.Sync pass. AuthOK is true exactly when the spoke's list call
// succeeded — i.e. cscli could read local_api_credentials.yaml and reach
// the local CrowdSec LAPI socket — independent of whether any entries
// still needed pushing.
func crowdSecStatusFromReport(allowlistName string, report trustednetworks.SyncReport) trustednetworks.CrowdSecAllowlistStatus {
	res := report.CrowdSec
	authOK := res.Enabled && len(res.Errors) == 0
	return trustednetworks.CrowdSecAllowlistStatus{
		AllowlistName: allowlistName,
		Configured:    true,
		AuthOK:        authOK,
		LastSyncAt:    time.Now().UTC(),
		DesiredCount:  report.RegistryCount,
		CurrentCount:  len(res.AlreadySynced) + len(res.Pushed),
		DriftCount:    len(res.Drift),
		Mode:          report.Mode,
	}
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
