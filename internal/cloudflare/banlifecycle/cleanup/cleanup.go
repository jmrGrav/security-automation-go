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
	ruleID := entry.RuleID
	if ruleID == "" {
		rules, err := loadRules()
		if err != nil {
			return fmt.Errorf("list autoban rules: %w", err)
		}
		ruleID = matchRuleByNote(rules, entry.IP)
		if ruleID == "" {
			// No matching CF rule found (already deleted, or never had one).
			// Treat as a successful no-op for idempotency.
			return w.finishCleanup(ctx, entry, "no matching Cloudflare rule found (already removed or never created)")
		}
	}

	if w.CF != nil {
		if err := w.CF.DeleteIPAccessRule(ctx, w.ZoneID, ruleID); err != nil {
			if !isNotFound(err) {
				return fmt.Errorf("delete rule %s: %w", ruleID, err)
			}
			// Already gone — idempotent no-op.
		}
	}

	reason := fmt.Sprintf("ban expired at %s (duration=%s, recidive_level=%d)",
		entry.ExpiresAt.UTC().Format(time.RFC3339), entry.Duration, entry.RecidiveLevel)
	return w.finishCleanup(ctx, entry, reason)
}

func (w *Worker) finishCleanup(ctx context.Context, entry banlifecycle.Entry, reason string) error {
	if err := w.Store.MarkStatus(ctx, entry.IP, banlifecycle.StatusExpiredCleaned, reason); err != nil {
		return fmt.Errorf("mark status: %w", err)
	}
	cleanedEntry := entry
	cleanedEntry.Status = banlifecycle.StatusExpiredCleaned
	if w.Audit != nil {
		if err := w.Audit.RecordDeban(ctx, cleanedEntry, reason); err != nil {
			w.logger().Warn("banlifecycle cleanup: audit record failed", "ip", entry.IP, "error", err)
		}
	}
	if w.Evidence != nil {
		if err := w.Evidence.RecordDebanEvidence(ctx, cleanedEntry, reason); err != nil {
			w.logger().Warn("banlifecycle cleanup: evidence record failed", "ip", entry.IP, "error", err)
		}
	}
	w.logger().Info("banlifecycle cleanup: rule expired and removed", "ip", entry.IP, "reason", reason)
	return nil
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
