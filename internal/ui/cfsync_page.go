package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/cloudflare/discovery"
	"github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/cloudflare/transport"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/httpclient"
)

// cfRuleInventoryCacheTTL bounds how often /sync makes a live, read-only
// Cloudflare API call (GET .../firewall/access_rules/rules) to count the
// zone's total IP access rules. Cloudflare's API is rate-limited and this
// call costs nothing operationally (no mutation), but it should not fire on
// every page load — 60s keeps it fresh without hammering the API on repeat
// visits (see issue #83: cf_ban_lifecycle only tracks tool-managed rules, so
// operators had no visibility into the much larger set of live CF rules).
const cfRuleInventoryCacheTTL = 60 * time.Second

// cfRuleInventory is a read-only snapshot comparing the zone's total live
// Cloudflare IP access rules (via discovery.ListIPAccessRules, the same
// read-only primitive used by the setup wizard's token validation) against
// the subset cf_ban_lifecycle tracks. It never writes anything — no
// synthetic/backfilled rows are created for untracked rules, since this tool
// has no way to know their origin or intended lifetime.
type cfRuleInventory struct {
	Wired          bool // false when no CF token/zone is configured
	Error          string
	LiveCount      int
	TrackedCount   int
	UntrackedCount int
}

// cfRuleInventorySnapshot returns the cached inventory, refreshing it via a
// live read-only Cloudflare API call when the cache has expired.
func (s *Server) cfRuleInventorySnapshot(ctx context.Context, trackedCount int) cfRuleInventory {
	s.cfInventoryMu.Lock()
	if !s.cfInventoryCacheAt.IsZero() && time.Since(s.cfInventoryCacheAt) < cfRuleInventoryCacheTTL {
		cached := s.cfInventoryCache
		s.cfInventoryMu.Unlock()
		return cached
	}
	s.cfInventoryMu.Unlock()

	inv := s.fetchCFRuleInventory(ctx, trackedCount)

	s.cfInventoryMu.Lock()
	s.cfInventoryCache = inv
	s.cfInventoryCacheAt = time.Now()
	s.cfInventoryMu.Unlock()

	return inv
}

func (s *Server) fetchCFRuleInventory(ctx context.Context, trackedCount int) cfRuleInventory {
	token := strings.TrimSpace(s.cfg.Cloudflare.APIToken)
	zoneID := strings.TrimSpace(s.cfZoneIDFromSetup(ctx))
	if token == "" || zoneID == "" {
		return cfRuleInventory{Wired: false}
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	listRules := s.cfRuleLister
	if listRules == nil {
		listRules = func(ctx context.Context, token, zoneID string) ([]models.IPAccessRule, error) {
			t := transport.New(httpclient.New(config.HTTPConfig{Timeout: 10 * time.Second}), token)
			return discovery.New(t).ListIPAccessRules(ctx, zoneID)
		}
	}
	rules, err := listRules(ctx, token, zoneID)
	if err != nil {
		return cfRuleInventory{Wired: true, Error: err.Error()}
	}

	liveCount := len(rules)
	untracked := liveCount - trackedCount
	if untracked < 0 {
		untracked = 0
	}
	return cfRuleInventory{
		Wired:          true,
		LiveCount:      liveCount,
		TrackedCount:   trackedCount,
		UntrackedCount: untracked,
	}
}

// buildCFSyncView reads the live Cloudflare ban-lifecycle state
// (banlifecycle.Store, backed by the scoped runtime.db) — the same store
// the reactive autoban/cleanup path writes to. This is the daemon's sole
// source of truth for "what Cloudflare rules does cf-sync currently
// manage"; there is no separate periodic sync-plan computation to read.
func (s *Server) buildCFSyncView(ctx context.Context) CFSyncView {
	mutationsOn := s.cfg != nil && s.cfg.Cloudflare.MutationsEnabled
	dryRun := !mutationsOn

	if s.banLifecycleStore == nil {
		return CFSyncView{Wired: false, MutationsOn: mutationsOn, DryRun: dryRun}
	}

	active, err := s.banLifecycleStore.Active(ctx)
	if err != nil {
		return CFSyncView{Wired: true, Error: err.Error(), MutationsOn: mutationsOn, DryRun: dryRun}
	}
	recent, err := s.banLifecycleStore.Recent(ctx, 500)
	if err != nil {
		return CFSyncView{Wired: true, Error: err.Error(), MutationsOn: mutationsOn, DryRun: dryRun}
	}

	counts := make(map[string]int, 8)
	var last time.Time
	for _, e := range recent {
		counts[e.Status]++
		if e.CreatedAt.After(last) {
			last = e.CreatedAt
		}
	}

	return CFSyncView{
		Wired:          true,
		MutationsOn:    mutationsOn,
		DryRun:         dryRun,
		HasActivity:    len(recent) > 0,
		ActiveCount:    len(active),
		StatusCounts:   counts,
		SampleSize:     len(recent),
		LastActivityAt: last,
		RuleInventory:  s.cfRuleInventorySnapshot(ctx, len(active)),
	}
}

func (s *Server) handleCFSyncPage(w http.ResponseWriter, r *http.Request) {
	view := s.buildCFSyncView(r.Context())
	_ = CFSyncPage(view).Render(r.Context(), w)
}

// CFSyncPage renders the /sync page.
func CFSyncPage(view CFSyncView) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "CF Ban Sync",
		Headline: "Cloudflare Ban Sync",
		Subtitle: "Live Cloudflare-managed ban state, sourced from the same lifecycle store the daemon uses to ban/clean up.",
		Active:   "/sync",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			return renderCFSyncBody(w, view)
		}),
	})
}

func renderCFSyncBody(w io.Writer, view CFSyncView) error {
	if view.Error != "" {
		_, err := fmt.Fprintf(w,
			`<div class="panel"><p class="error">Error loading Cloudflare ban lifecycle data: %s</p></div>`,
			html.EscapeString(view.Error),
		)
		return err
	}

	if !view.Wired {
		_, err := fmt.Fprint(w,
			`<div class="panel"><p class="error">Cloudflare ban lifecycle store is not configured in this build.</p></div>`,
		)
		return err
	}

	modeBadge := `<span class="badge healthy">MUTATIONS ON</span>`
	if view.DryRun {
		modeBadge = `<span class="badge warning">DRY-RUN</span>`
	}

	if !view.HasActivity {
		if _, err := fmt.Fprintf(w,
			`<div class="panel"><div class="badges" style="margin-bottom:.75rem">%s</div>`+
				`<p class="muted">No Cloudflare-managed bans recorded yet. The daemon bans/cleans up reactively as CrowdSec and WAF events arrive — entries will appear here once it processes its first ban.</p></div>`,
			modeBadge,
		); err != nil {
			return err
		}
		return renderCFRuleInventory(w, view.RuleInventory)
	}

	if _, err := fmt.Fprintf(w,
		`<div class="panel"><h2>Live Managed State</h2>`+
			`<div class="badges" style="margin-bottom:.75rem">%s</div>`+
			`<div class="kv">`+
			`<div class="row"><span>Active managed bans</span><span>%d</span></div>`+
			`<div class="row"><span>Most recent activity</span><span>%s (%s ago)</span></div>`+
			`</div></div>`,
		modeBadge,
		view.ActiveCount,
		html.EscapeString(view.LastActivityAt.UTC().Format(time.RFC3339)),
		html.EscapeString(time.Since(view.LastActivityAt).Truncate(time.Second).String()),
	); err != nil {
		return err
	}

	if err := renderCFSyncStatusBreakdown(w, view.StatusCounts, view.SampleSize); err != nil {
		return err
	}

	if _, err := fmt.Fprint(w,
		`<div class="panel"><p class="muted">Full per-IP history and operator deban actions live at `+
			`<a href="/ban-lifecycle">/ban-lifecycle</a>.</p></div>`,
	); err != nil {
		return err
	}

	return renderCFRuleInventory(w, view.RuleInventory)
}

// renderCFRuleInventory shows the read-only cross-reference of total live
// Cloudflare rules vs the subset cf_ban_lifecycle tracks (issue #83). It
// never proposes or performs a backfill — untracked rules are reported as a
// plain count with an explanation, since this tool has no way to know their
// origin or intended lifetime.
func renderCFRuleInventory(w io.Writer, inv cfRuleInventory) error {
	if !inv.Wired {
		_, err := fmt.Fprint(w,
			`<div class="panel"><h2>Cloudflare Rule Inventory</h2>`+
				`<p class="muted">Not available — no Cloudflare API token/zone configured in this build.</p></div>`,
		)
		return err
	}
	if inv.Error != "" {
		_, err := fmt.Fprintf(w,
			`<div class="panel"><h2>Cloudflare Rule Inventory</h2>`+
				`<p class="error">Could not list live Cloudflare rules: %s</p></div>`,
			html.EscapeString(inv.Error),
		)
		return err
	}
	_, err := fmt.Fprintf(w,
		`<div class="panel"><h2>Cloudflare Rule Inventory</h2>`+
			`<p class="muted">Read-only comparison against the zone's live IP access rules (refreshed every %s).</p>`+
			`<div class="kv">`+
			`<div class="row"><span>Live rules in zone</span><span>%d</span></div>`+
			`<div class="row"><span>Tracked by cf_ban_lifecycle</span><span>%d</span></div>`+
			`<div class="row"><span>Untracked (pre-existing or created outside this tool)</span><span>%d</span></div>`+
			`</div></div>`,
		cfRuleInventoryCacheTTL,
		inv.LiveCount,
		inv.TrackedCount,
		inv.UntrackedCount,
	)
	return err
}

func renderCFSyncStatusBreakdown(w io.Writer, counts map[string]int, sampleSize int) error {
	if _, err := fmt.Fprintf(w,
		`<div class="panel"><h2>Status Breakdown</h2><p class="muted">Across the most recent %d tracked entries.</p><div class="kv">`,
		sampleSize,
	); err != nil {
		return err
	}

	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, status := range keys {
		if _, err := fmt.Fprintf(w,
			`<div class="row"><span>%s</span><span>%d</span></div>`,
			html.EscapeString(status), counts[status],
		); err != nil {
			return err
		}
	}

	_, err := fmt.Fprint(w, `</div></div>`)
	return err
}
