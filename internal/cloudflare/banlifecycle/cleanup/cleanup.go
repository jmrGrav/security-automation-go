// Package cleanup implements the periodic worker that removes Cloudflare
// autoban access rules once their banlifecycle.Entry has expired.
//
// The worker depends only on banlifecycle.Store plus the small local
// interfaces declared in this file, so it can be exercised in tests with
// the banlifecycle/memstore fake and a fake Cloudflare client — no SQLite,
// no real Cloudflare client, no import of internal/cloudflare.
package cleanup

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
)

// AutobanNotePrefix is the notes prefix used by cfBanExecutor when creating
// Cloudflare access rules for autoban decisions. Used as a fallback lookup
// key when a tracked entry's RuleID is empty (e.g. the AddIPAccessRule
// response didn't carry an ID, or the local row was created before the ID
// was persisted). This worker NEVER deletes a rule whose note does not
// carry this prefix, and NEVER deletes a rule for an IP that isn't tracked
// in Store — manually-created rules and CrowdSec-driven rules (different
// note prefixes) are always left alone.
const AutobanNotePrefix = "cf-sync:autoban:"

// CFRule is the minimal view of a Cloudflare IP access rule needed for the
// note-based fallback lookup.
type CFRule struct {
	ID    string
	Notes string
	IP    string // Configuration.Value, normalized
}

// CFRuleLister lists current Cloudflare IP access rules for a zone, used
// only as a fallback when a tracked entry's RuleID is empty.
type CFRuleLister interface {
	ListAutobanRules(ctx context.Context, zoneID string) ([]CFRule, error)
}

// CFRuleDeleter deletes a Cloudflare IP access rule by its ID. Implementations
// MUST treat "rule already gone" (e.g. a 404 from the Cloudflare API) as a
// successful no-op so repeated cleanup ticks remain idempotent.
type CFRuleDeleter interface {
	DeleteIPAccessRule(ctx context.Context, zoneID, ruleID string) error
}

// CFClient is the full dependency surface the worker needs from Cloudflare.
type CFClient interface {
	CFRuleLister
	CFRuleDeleter
}

// AuditSink records an audit-trail entry for a deban action. Kept minimal
// and local so this package never needs to import the runtime/events or
// sqlite packages.
type AuditSink interface {
	RecordDeban(ctx context.Context, e banlifecycle.Entry, reason string) error
}

// EvidenceSink records an evidence entry for a deban action.
type EvidenceSink interface {
	RecordDebanEvidence(ctx context.Context, e banlifecycle.Entry, reason string) error
}

// Worker periodically scans banlifecycle.Store for expired entries and
// removes the corresponding Cloudflare access rule.
type Worker struct {
	Store    banlifecycle.Store
	CF       CFClient
	ZoneID   string
	Audit    AuditSink
	Evidence EvidenceSink
	Logger   *slog.Logger

	// Now is overridable for tests; defaults to time.Now.
	Now func() time.Time
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Worker) logger() *slog.Logger {
	if w.Logger != nil {
		return w.Logger
	}
	return slog.Default()
}

// Run executes one cleanup pass: find every expired active entry, delete
// its Cloudflare rule (by RuleID, falling back to note-based lookup when
// RuleID is empty), mark the entry expired_cleaned, and write an audit +
// evidence record. Errors for individual entries are logged and do not
// abort the pass; Run returns the first error only if the store scan
// itself (Expired) fails.
func (w *Worker) Run(ctx context.Context) error {
	if w == nil || w.Store == nil {
		return nil
	}
	now := w.now()
	expired, err := w.Store.Expired(ctx, now)
	if err != nil {
		return fmt.Errorf("banlifecycle/cleanup: Store.Expired: %w", err)
	}
	if len(expired) == 0 {
		return nil
	}

	var rulesCache []CFRule
	var rulesCacheLoaded bool
	loadRules := func() ([]CFRule, error) {
		if rulesCacheLoaded {
			return rulesCache, nil
		}
		if w.CF == nil {
			rulesCacheLoaded = true
			return nil, nil
		}
		rules, err := w.CF.ListAutobanRules(ctx, w.ZoneID)
		if err != nil {
			return nil, err
		}
		rulesCache = rules
		rulesCacheLoaded = true
		return rulesCache, nil
	}

	for _, entry := range expired {
		if err := w.cleanupOne(ctx, entry, loadRules); err != nil {
			w.logger().Error("banlifecycle cleanup: failed to clean entry",
				"ip", entry.IP, "rule_id", entry.RuleID, "error", err)
		}
	}
	return nil
}

func (w *Worker) cleanupOne(ctx context.Context, entry banlifecycle.Entry, loadRules func() ([]CFRule, error)) error {
	reason := fmt.Sprintf("ban expired at %s (duration=%s, recidive_level=%d)",
		entry.ExpiresAt.UTC().Format(time.RFC3339), entry.Duration, entry.RecidiveLevel)
	return w.deleteRuleAndFinish(ctx, entry, loadRules, banlifecycle.StatusExpiredCleaned, reason)
}

// deleteRuleAndFinish deletes the Cloudflare rule tracked by entry (by
// RuleID, falling back to note-based lookup when empty, treating "already
// gone" as a successful no-op), then marks the entry with the given status
// and writes the audit/evidence trail. This is the single idempotent
// delete-and-record sequence shared by the automatic expiry cleanup pass
// (Run) and operator-initiated deban actions (DebanOne, ClearAll) — the
// only difference between those callers is the resulting status and the
// human-readable reason.
func (w *Worker) deleteRuleAndFinish(ctx context.Context, entry banlifecycle.Entry, loadRules func() ([]CFRule, error), status, reason string) error {
	ruleID := entry.RuleID
	if ruleID == "" {
		rules, err := loadRules()
		if err != nil {
			return fmt.Errorf("list autoban rules: %w", err)
		}
		ruleID = matchRuleByNote(rules, entry.IP)
	}

	if ruleID != "" && w.CF != nil {
		if err := w.CF.DeleteIPAccessRule(ctx, w.ZoneID, ruleID); err != nil {
			if !isNotFound(err) {
				return fmt.Errorf("delete rule %s: %w", ruleID, err)
			}
			// Already gone — idempotent no-op.
		}
	}

	return w.finishCleanup(ctx, entry, status, reason)
}

func (w *Worker) finishCleanup(ctx context.Context, entry banlifecycle.Entry, status, reason string) error {
	if err := w.Store.MarkStatus(ctx, entry.IP, status, reason); err != nil {
		return fmt.Errorf("mark status: %w", err)
	}
	finishedEntry := entry
	finishedEntry.Status = status
	if w.Audit != nil {
		if err := w.Audit.RecordDeban(ctx, finishedEntry, reason); err != nil {
			w.logger().Warn("banlifecycle cleanup: audit record failed", "ip", entry.IP, "error", err)
		}
	}
	if w.Evidence != nil {
		if err := w.Evidence.RecordDebanEvidence(ctx, finishedEntry, reason); err != nil {
			w.logger().Warn("banlifecycle cleanup: evidence record failed", "ip", entry.IP, "error", err)
		}
	}
	w.logger().Info("banlifecycle cleanup: rule removed", "ip", entry.IP, "status", status, "reason", reason)
	return nil
}

// DebanOne is the operator-initiated counterpart to the automatic expiry
// cleanup: it removes the Cloudflare rule for a single managed IP (idempotent,
// same delete-by-RuleID-or-note-fallback logic as Run) and marks the entry
// StatusOperatorDebanned with the operator-supplied reason. It only ever
// touches banlifecycle.Store and the Cloudflare rule — it never reads or
// writes AbuseIPDB report data, dedup state, or reporting windows, since
// debanning from Cloudflare must never be conflated with erasing AbuseIPDB
// history.
//
// Returns an error if ip has no tracked entry at all. Debanning an IP that
// is already expired_cleaned/auto_debanned/operator_debanned is allowed and
// idempotent (it simply re-confirms the Cloudflare rule is gone and updates
// the status/reason).
func (w *Worker) DebanOne(ctx context.Context, ip, reason string) (banlifecycle.Entry, error) {
	if w == nil || w.Store == nil {
		return banlifecycle.Entry{}, fmt.Errorf("banlifecycle/cleanup: worker not configured")
	}
	entry, found, err := w.Store.Get(ctx, ip)
	if err != nil {
		return banlifecycle.Entry{}, fmt.Errorf("get entry for %s: %w", ip, err)
	}
	if !found {
		return banlifecycle.Entry{}, fmt.Errorf("no tracked ban lifecycle entry for %s", ip)
	}
	if reason == "" {
		reason = "operator-initiated deban"
	}
	var rulesCache []CFRule
	var rulesCacheLoaded bool
	loadRules := func() ([]CFRule, error) {
		if rulesCacheLoaded {
			return rulesCache, nil
		}
		if w.CF == nil {
			rulesCacheLoaded = true
			return nil, nil
		}
		rules, err := w.CF.ListAutobanRules(ctx, w.ZoneID)
		if err != nil {
			return nil, err
		}
		rulesCache = rules
		rulesCacheLoaded = true
		return rulesCache, nil
	}
	if err := w.deleteRuleAndFinish(ctx, entry, loadRules, banlifecycle.StatusOperatorDebanned, reason); err != nil {
		return banlifecycle.Entry{}, err
	}
	entry.Status = banlifecycle.StatusOperatorDebanned
	return entry, nil
}

// ClearResult summarizes the outcome of a bulk ClearAll pass.
type ClearResult struct {
	Attempted int
	Deleted   int
	Skipped   int
	Failed    int
	Errors    []string
}

// ClearAll debans every currently-active managed IP (banlifecycle.Store.Active),
// one at a time, via the same idempotent delete-by-RuleID-or-note-fallback
// path as DebanOne. It never touches AbuseIPDB data or any IP outside the
// managed banlifecycle.Store — manually-created Cloudflare rules and
// CrowdSec-driven rules are never enumerated or deleted by this call.
//
// A small delay between deletes is used to avoid bursting the Cloudflare
// API when clearing many entries at once; callers needing tighter control
// over the request budget should wrap the worker's CF client in their own
// rate limiter.
func (w *Worker) ClearAll(ctx context.Context, reason string) (ClearResult, error) {
	var result ClearResult
	if w == nil || w.Store == nil {
		return result, fmt.Errorf("banlifecycle/cleanup: worker not configured")
	}
	active, err := w.Store.Active(ctx)
	if err != nil {
		return result, fmt.Errorf("banlifecycle/cleanup: Store.Active: %w", err)
	}
	if reason == "" {
		reason = "operator-initiated bulk clear"
	}
	result.Attempted = len(active)
	for i, entry := range active {
		if ctx.Err() != nil {
			result.Failed += len(active) - i
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", entry.IP, ctx.Err()))
			break
		}
		if _, err := w.DebanOne(ctx, entry.IP, reason); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", entry.IP, err))
			continue
		}
		result.Deleted++
		if i < len(active)-1 {
			select {
			case <-ctx.Done():
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	return result, nil
}

// matchRuleByNote finds the Cloudflare rule for ip whose Notes carries the
// AutobanNotePrefix tag (the redundant note-based fallback identification
// scheme; see cfBanExecutor in cmd/cf-sync for where the note is written).
func matchRuleByNote(rules []CFRule, ip string) string {
	for _, r := range rules {
		if r.IP != ip {
			continue
		}
		if strings.HasPrefix(r.Notes, AutobanNotePrefix) {
			return r.ID
		}
	}
	return ""
}

// isNotFound reports whether err represents a "rule already gone" condition
// that should be treated as a successful no-op by the cleanup worker. The
// underlying Cloudflare transport wraps HTTP errors as plain strings (no
// typed not-found error exists today), so this matches on the embedded
// status code/text as a pragmatic fallback.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "404") || strings.Contains(msg, "not found") || strings.Contains(msg, "could not find")
}
