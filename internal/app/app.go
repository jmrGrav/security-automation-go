package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/jm/security-automation-go/internal/abuseipdb"
	cloudflareevent "github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/betterstack"
	"github.com/jm/security-automation-go/internal/cidrban"
	"github.com/jm/security-automation-go/internal/cloudflare"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/crowdsec"
	csmodels "github.com/jm/security-automation-go/internal/crowdsec/models"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/logging"
	luastate "github.com/jm/security-automation-go/internal/openresty/state"
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
	csAllowlist crowdsec.AllowlistManager // for per-cycle allowlist fetch
	abuse       *abuseipdb.Client
	better      betterstack.IngestClient
	recidiv     recidive.Service
	cidr        cidrban.Service

	// Anti-self-ban shield (P0 safety).
	shield *protected.Shield

	// Shadow mode: compute plans but do not mutate Cloudflare.
	shadowMode   bool
	shadowStore  *shadow.Store
	shadowReport string // path to SHADOW_MODE_REPORT.md

	// luaWriter publishes bans.json for the OpenResty Lua bouncer (optional).
	luaWriter *luastate.Writer
}

// ── allowlistSet ─────────────────────────────────────────────────────────────

// allowlistSet is a compiled view of the CrowdSec allowlist for fast lookup.
// Mirrors Python's is_allowlisted(): direct IP match, then CIDR coverage.
type allowlistSet struct {
	ips  map[string]bool // normalized IP string → bool
	nets []*net.IPNet    // CIDR entries from the allowlist
}

func newAllowlistSet(entries []csmodels.AllowlistEntry) *allowlistSet {
	s := &allowlistSet{ips: make(map[string]bool)}
	for _, e := range entries {
		if ip := net.ParseIP(e.Value); ip != nil {
			s.ips[ip.String()] = true
		} else if _, cidr, err := net.ParseCIDR(e.Value); err == nil {
			s.nets = append(s.nets, cidr)
		}
	}
	return s
}

// contains mirrors Python's is_allowlisted(): direct IP match then CIDR coverage.
// Returns false if ipStr is not a valid IP (Python: except ValueError: pass).
func (s *allowlistSet) contains(ipStr string) bool {
	if s == nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if s.ips[ip.String()] {
		return true
	}
	for _, cidr := range s.nets {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// asMap returns the direct-IP entries as a map[string]bool for the drift classifier.
// CIDR-allowlisted IPs that appear as drift strings are not expanded here.
func (s *allowlistSet) asMap() map[string]bool {
	if s == nil {
		return nil
	}
	return s.ips
}

// fetchAllowlist retrieves the CrowdSec allowlist for the current cycle.
// Fail-open on error: returns nil (no filter applied), matching Python's
// circuit-breaker behavior which returns set() on failure.
func (a *CrowdSecSyncApp) fetchAllowlist(ctx context.Context) *allowlistSet {
	if a.csAllowlist == nil {
		return nil
	}
	entries, err := a.csAllowlist.ListAllowlist(ctx, a.cfg.CrowdSec.AllowlistName)
	if err != nil {
		a.logger.WarnContext(ctx, "allowlist fetch failed (fail-open)",
			"name", a.cfg.CrowdSec.AllowlistName, "error", err)
		return nil
	}
	return newAllowlistSet(entries)
}

// newLuaWriter creates a luastate.Writer from config, or nil if push is disabled.
func newLuaWriter(cfg *config.Config) *luastate.Writer {
	if !cfg.OpenResty.LuaStatePushEnable {
		return nil
	}
	hostname, _ := os.Hostname()
	return luastate.New(luastate.Config{
		Path:       cfg.OpenResty.LuaStatePath,
		ShadowPath: cfg.OpenResty.ShadowLuaStatePath,
		Hostname:   hostname,
		PID:        os.Getpid(),
	})
}

// pushLuaState writes bans.json for the OpenResty Lua bouncer.
// Source: active CrowdSec bans + active CIDR bans from cidrban state.
// Applies shield + allowlist filters. Skipped if luaWriter is nil.
func (a *CrowdSecSyncApp) pushLuaState(ctx context.Context, logger *slog.Logger) {
	if a.luaWriter == nil {
		return
	}

	bans, err := a.cs.ListActiveBans(ctx)
	if err != nil {
		logger.WarnContext(ctx, "lua state push: ListActiveBans failed (skip)", "error", err)
		return
	}

	// Load allowlist for the filter.
	allowlist := a.fetchAllowlist(ctx)
	filter := luastate.FilterFunc(func(ip string) bool {
		if a.shield != nil && a.shield.IsProtected(ip) {
			return true
		}
		return allowlist.contains(ip)
	})

	// Read active CIDR bans from cidrban state file.
	cidrs := loadActiveCIDRs(a.cfg.StateDir)

	if err := a.luaWriter.Write(ctx, bans, cidrs, filter); err != nil {
		logger.WarnContext(ctx, "lua state push failed (non-fatal)", "error", err)
	}
}

// loadActiveCIDRs reads the cidrban state file and returns non-expired /24 entries.
func loadActiveCIDRs(stateDir string) []string {
	data, err := os.ReadFile(filepath.Join(stateDir, "cidr-banned.json"))
	if err != nil {
		return nil
	}
	var m map[string]struct {
		BannedAt string `json:"banned_at"`
		IPCount  int    `json:"ip_count"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	expiry := 24 * time.Hour
	now := time.Now().UTC()
	var cidrs []string
	for cidr, entry := range m {
		t, err := time.Parse(time.RFC3339Nano, entry.BannedAt)
		if err != nil {
			t, err = time.Parse(time.RFC3339, entry.BannedAt)
		}
		if err == nil && now.Sub(t.UTC()) < expiry {
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs
}

// cidrBanSourceAdapter adapts crowdsec.ActiveBanSource → cidrban.RecentBanSource.
//
// Applies both the anti-self-ban shield and the CrowdSec allowlist filter,
// mirroring Python's sync_cidr_bans() which calls is_protected() and
// is_allowlisted() before grouping IPs by /24.
type cidrBanSourceAdapter struct {
	src           crowdsec.ActiveBanSource
	shield        *protected.Shield
	csAllowlist   crowdsec.AllowlistManager // nil → no allowlist filter
	allowlistName string
}

func (a *cidrBanSourceAdapter) ListRecentBans(ctx context.Context) ([]cidrban.Ban, error) {
	bans, err := a.src.ListRecentBans(ctx)
	if err != nil {
		return nil, err
	}

	// Fetch allowlist for this CIDR cycle (mirrors Python's cs_allowlist parameter).
	// Fail-open on error: nil allowlist means no IPs are filtered.
	var al *allowlistSet
	if a.csAllowlist != nil {
		entries, alErr := a.csAllowlist.ListAllowlist(ctx, a.allowlistName)
		if alErr == nil {
			al = newAllowlistSet(entries)
		}
	}

	out := make([]cidrban.Ban, 0, len(bans))
	for _, b := range bans {
		if a.shield != nil && a.shield.IsProtected(b.IP) {
			continue // P0: never count a protected IP
		}
		if al.contains(b.IP) {
			continue // Allowlist: mirrors Python's is_allowlisted() check
		}
		out = append(out, cidrban.Ban{IP: b.IP, When: b.When})
	}
	return out, nil
}

// recidiveBanSourceAdapter adapts crowdsec.ActiveBanSource → recidive.RecentBanSource.
// Applies shield and allowlist filters identically to cidrBanSourceAdapter so that
// the same protections apply to recidive tracking as to CIDR aggregation.
// crowdsec.Client.ListRecentBans() already filters by LOCAL_ORIGINS; no extra origin filter needed.
type recidiveBanSourceAdapter struct {
	src           crowdsec.ActiveBanSource
	shield        *protected.Shield
	csAllowlist   crowdsec.AllowlistManager
	allowlistName string
}

func (a *recidiveBanSourceAdapter) ListRecentBans(ctx context.Context) ([]recidive.Ban, error) {
	bans, err := a.src.ListRecentBans(ctx)
	if err != nil {
		return nil, err
	}
	var al *allowlistSet
	if a.csAllowlist != nil {
		entries, alErr := a.csAllowlist.ListAllowlist(ctx, a.allowlistName)
		if alErr == nil {
			al = newAllowlistSet(entries)
		}
	}
	out := make([]recidive.Ban, 0, len(bans))
	for _, b := range bans {
		if a.shield != nil && a.shield.IsProtected(b.IP) {
			continue
		}
		if al.contains(b.IP) {
			continue
		}
		out = append(out, recidive.Ban{IP: b.IP, Scenario: b.Scenario, When: b.When, ID: b.ID})
	}
	return out, nil
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

	shield := protected.New()

	return &CrowdSecSyncApp{
		logger:      logger,
		cfg:         cfg,
		store:       state.NewJSONStore(cfg.StateDir),
		cf:          cfClient,
		cs:          csClient,
		csDecisions: csClient,
		csAllowlist: csClient,
		abuse:       abuse,
		better:      betterstack.NewClient(httpClient, cfg.BetterStack.SourceToken, cfg.BetterStack.IngestingHost),
		recidiv: recidive.NewService(recidive.Config{
			StateDir: cfg.StateDir,
			BanSource: &recidiveBanSourceAdapter{
				src:           csClient,
				shield:        shield,
				csAllowlist:   csClient,
				allowlistName: cfg.CrowdSec.AllowlistName,
			},
			Escalator: csClient,
		}),
		cidr: cidrban.NewService(cidrban.Config{
			StateDir: cfg.StateDir,
			BanSource: &cidrBanSourceAdapter{
				src:           csClient,
				shield:        shield,
				csAllowlist:   csClient,
				allowlistName: cfg.CrowdSec.AllowlistName,
			},
			CFBanner:      cfClient,
			CFRuleGetter:  cfClient,
			CFDeleter:     cfClient,
			CSRangeBanner: csClient,
			ZoneID:        cfg.Cloudflare.ZoneID,
		}),
		shield:       shield,
		shadowStore:  shadow.NewStore(cfg.StateDir),
		shadowReport: filepath.Join(cfg.StateDir, "SHADOW_MODE_REPORT.md"),
		luaWriter:    newLuaWriter(cfg),
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

		// Core enforcement loop: CrowdSec active bans → Cloudflare IP rules.
		if err := a.syncCloudflare(runCtx, l); err != nil {
			l.WarnContext(runCtx, "cf sync failed (non-fatal)", "error", err)
		}

		// Subsidiary enforcement features.
		// cidrban is suppressed in shadow mode: it calls AddIPAccessRule (CF mutation)
		// which would break the "Go does not mutate Cloudflare" invariant of shadow mode.
		// recidiv and modsec are currently no-ops (nil deps) so they are not guarded.
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

		// AbuseIPDB reporting pipeline (CrowdSec events, OpenResty, outbox).
		wafRuntime.processCrowdSec(runCtx, l)
		wafRuntime.processOpenResty(runCtx, l)
		wafRuntime.processOutbox(runCtx, l)

		// Lua/OpenResty state push (optional; suppressed in shadow mode).
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

// buildSyncPlan computes what Go would add/remove without executing anything.
// Applies (in order, mirroring Python's sync_cloudflare()):
//  1. IP normalization
//  2. Anti-self-ban shield (P0)
//  3. CrowdSec allowlist filter (is_allowlisted)
func (a *CrowdSecSyncApp) buildSyncPlan(
	ctx context.Context,
	activeBans []string,
	cfRules map[string]string, // ip → ruleID
) shadow.SyncPlan {
	// Fetch allowlist once for this plan computation.
	// Fail-open: nil allowlist → no IPs filtered (matching Python circuit-breaker).
	allowlist := a.fetchAllowlist(ctx)

	banSet := make(map[string]bool, len(activeBans))
	for _, ip := range activeBans {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		norm := parsed.String()
		// P0: never ban protected ranges (RFC1918, CF, host own IPs).
		if a.shield != nil && a.shield.IsProtected(norm) {
			continue
		}
		// Allowlist filter: mirrors Python's is_allowlisted() in sync_cloudflare().
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
			// Fetch current allowlist for drift classification so allowlist-filtered
			// IPs are labeled DriftAllowlist rather than DriftConfidenceGate/Timing.
			// Previously passed as nil, causing misclassification.
			allowlist := a.fetchAllowlist(ctx)
			allowlistMap := allowlist.asMap()

			// SHADOW_MODE_REPORT.md — per-cycle agreement metrics
			if err := shadow.WriteReport(a.shadowReport, cycles); err != nil {
				logger.WarnContext(ctx, "shadow report write failed", "error", err)
			}
			// SHADOW_DRIFT_ANALYSIS.md — drift classification and remediation list
			driftPath := filepath.Join(reportDir, "SHADOW_DRIFT_ANALYSIS.md")
			if err := shadow.WriteDriftAnalysis(driftPath, cycles, isProtected, allowlistMap); err != nil {
				logger.WarnContext(ctx, "drift analysis write failed", "error", err)
			}
			// PYTHON_GO_PARITY_REPORT.md — feature gap cross-reference
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
