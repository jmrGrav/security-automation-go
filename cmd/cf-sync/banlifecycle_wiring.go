package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	cfpkg "github.com/jm/security-automation-go/internal/cloudflare"
	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle/cleanup"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	runtimemodels "github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

// cfCleanupAdapter adapts a cfpkg.EnforcementClient to cleanup.CFClient,
// translating the autoban note prefix lookup into the underlying
// cloudflare client call.
type cfCleanupAdapter struct {
	client cfpkg.EnforcementClient
}

func (a *cfCleanupAdapter) ListAutobanRules(ctx context.Context, zoneID string) ([]cleanup.CFRule, error) {
	rules, err := a.client.ListIPAccessRulesByNotePrefix(ctx, zoneID, cleanup.AutobanNotePrefix)
	if err != nil {
		return nil, err
	}
	out := make([]cleanup.CFRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, cleanup.CFRule{ID: r.ID, Notes: r.Notes, IP: r.Configuration.Value})
	}
	return out, nil
}

func (a *cfCleanupAdapter) DeleteIPAccessRule(ctx context.Context, zoneID, ruleID string) error {
	return a.client.DeleteIPAccessRule(ctx, zoneID, ruleID)
}

var _ cleanup.CFClient = (*cfCleanupAdapter)(nil)

// journalAuditSink adapts a journal.JournalStore to cleanup.AuditSink,
// writing one audit.jsonl entry per deban so the action is traceable
// alongside every other runtime audit event.
type journalAuditSink struct {
	journal journal.JournalStore
}

func (s *journalAuditSink) RecordDeban(_ context.Context, e banlifecycle.Entry, reason string) error {
	if s == nil || s.journal == nil {
		return nil
	}
	return s.journal.Append(runtimemodels.AuditEvent{
		Timestamp: time.Now().UTC(),
		Status:    "completed",
		Target:    e.IP,
		Metadata: map[string]any{
			"event":          "cf_ban_lifecycle_deban",
			"ip":             e.IP,
			"rule_id":        e.RuleID,
			"reason":         reason,
			"ban_reason":     e.Reason,
			"recidive_level": e.RecidiveLevel,
			"created_at":     e.CreatedAt.UTC().Format(time.RFC3339),
			"expires_at":     e.ExpiresAt.UTC().Format(time.RFC3339),
		},
	})
}

var _ cleanup.AuditSink = (*journalAuditSink)(nil)

// reportingEvidenceSink adapts a reporting.EvidenceStore to
// cleanup.EvidenceSink, so every deban produces a DecisionEvidence record
// alongside the audit entry.
type reportingEvidenceSink struct {
	store reporting.EvidenceStore
}

func (s *reportingEvidenceSink) RecordDebanEvidence(ctx context.Context, e banlifecycle.Entry, reason string) error {
	if s == nil || s.store == nil {
		return nil
	}
	evidenceID := fmt.Sprintf("cf-ban-lifecycle:%s:%d", e.IP, e.CreatedAt.UTC().UnixNano())
	return s.store.Append(ctx, reporting.DecisionEvidence{
		EvidenceID:       evidenceID,
		Timestamp:        time.Now().UTC(),
		Source:           "cf_ban_lifecycle",
		IP:               e.IP,
		Decision:         "auto_debanned",
		Comment:          reason,
		CloudflareBanned: false,
		Metadata: map[string]any{
			"rule_id":        e.RuleID,
			"ban_reason":     e.Reason,
			"recidive_level": e.RecidiveLevel,
			"duration":       e.Duration.String(),
			"created_at":     e.CreatedAt.UTC().Format(time.RFC3339),
			"expires_at":     e.ExpiresAt.UTC().Format(time.RFC3339),
		},
	})
}

var _ cleanup.EvidenceSink = (*reportingEvidenceSink)(nil)

// startBanLifecycleCleanup launches the periodic Cloudflare autoban rule
// cleanup worker. It is a no-op if store or cf is nil (e.g. SQLite or the
// Cloudflare enforcement client is unavailable).
func startBanLifecycleCleanup(ctx context.Context, logger *slog.Logger, store banlifecycle.Store, cf cfpkg.EnforcementClient, zoneID string, interval time.Duration, auditJournal journal.JournalStore, evidenceStore reporting.EvidenceStore) {
	if store == nil || cf == nil {
		return
	}
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	if logger == nil {
		logger = slog.Default()
	}
	worker := &cleanup.Worker{
		Store:    store,
		CF:       &cfCleanupAdapter{client: cf},
		ZoneID:   zoneID,
		Audit:    &journalAuditSink{journal: auditJournal},
		Evidence: &reportingEvidenceSink{store: evidenceStore},
		Logger:   logger,
	}
	go func() {
		runCleanupOnce(ctx, logger, worker)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runCleanupOnce(ctx, logger, worker)
			}
		}
	}()
}

func runCleanupOnce(parent context.Context, logger *slog.Logger, worker *cleanup.Worker) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	if err := worker.Run(ctx); err != nil {
		logger.Warn("cf ban lifecycle cleanup failed", "error", err)
	}
}
