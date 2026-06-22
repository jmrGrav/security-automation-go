package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	cfpkg "github.com/jm/security-automation-go/internal/cloudflare"
	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/crowdsec"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	runtimemodels "github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/security/autodeban"
	"github.com/jm/security-automation-go/internal/security/reputation"
	sectrust "github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

// autodebanEvidenceAdapter adapts a reporting.EvidenceStore's Search method
// to autodeban.EvidenceStore's narrow shape. Used for BOTH the
// no-new-events deban trigger and the recent-hostile-event hard exclusion —
// see autodeban.EvidenceStore's doc comment. A nil store fails closed on
// both checks (Service.evaluateEntry treats a Search error as
// "cannot positively rule out recent hostile activity", never as "quiet").
type autodebanEvidenceAdapter struct {
	store reporting.EvidenceStore
}

func (a *autodebanEvidenceAdapter) Search(ctx context.Context, opts autodeban.EvidenceSearchOptions) ([]autodeban.EvidenceRecord, error) {
	if a == nil || a.store == nil {
		return nil, fmt.Errorf("autodeban: no evidence store configured")
	}
	records, err := a.store.Search(ctx, reporting.EvidenceSearchOptions{IP: opts.IP, From: opts.From})
	if err != nil {
		return nil, err
	}
	out := make([]autodeban.EvidenceRecord, 0, len(records))
	for _, r := range records {
		out = append(out, autodeban.EvidenceRecord{Timestamp: r.Timestamp, AbuseType: r.AbuseType})
	}
	return out, nil
}

var _ autodeban.EvidenceStore = (*autodebanEvidenceAdapter)(nil)

// autodebanEvidenceWriter adapts a reporting.EvidenceStore's Append method to
// autodeban.DebanEvidenceWriter, recording a DecisionEvidence row for every
// deban decision (shadow or enforced) alongside the audit entry.
type autodebanEvidenceWriter struct {
	store reporting.EvidenceStore
}

func (w *autodebanEvidenceWriter) WriteDebanEvidence(ctx context.Context, ip, ruleID, reason, note string, at time.Time) error {
	if w == nil || w.store == nil {
		return nil
	}
	evidenceID := fmt.Sprintf("autodeban:%s:%d", ip, at.UnixNano())
	return w.store.Append(ctx, reporting.DecisionEvidence{
		EvidenceID:       evidenceID,
		Timestamp:        at,
		Source:           "autodeban",
		IP:               ip,
		RuleID:           ruleID,
		Decision:         "auto_debanned",
		Comment:          note,
		CloudflareBanned: false,
		Metadata: map[string]any{
			"trigger_reason": reason,
		},
	})
}

var _ autodeban.DebanEvidenceWriter = (*autodebanEvidenceWriter)(nil)

// autodebanJournalAuditSink adapts a journal.JournalStore to
// autodeban.AuditSink's Record(action, fields) shape — distinct from
// cleanup.AuditSink's RecordDeban shape used by the expiry-based cleanup
// worker (see banlifecycle_wiring.go's journalAuditSink).
type autodebanJournalAuditSink struct {
	journal journal.JournalStore
}

func (s *autodebanJournalAuditSink) Record(action string, fields map[string]string) {
	if s == nil || s.journal == nil {
		return
	}
	metadata := make(map[string]any, len(fields)+1)
	metadata["event"] = action
	for k, v := range fields {
		metadata[k] = v
	}
	_ = s.journal.Append(runtimemodels.AuditEvent{
		Timestamp: time.Now().UTC(),
		Status:    "completed",
		Target:    fields["ip"],
		Metadata:  metadata,
	})
}

var _ autodeban.AuditSink = (*autodebanJournalAuditSink)(nil)

// crowdsecActiveBansChecker adapts crowdsec.Client.ListActiveBans to
// autodeban.CrowdSecListActiveBans's functional-adapter signature.
func crowdsecActiveBansChecker(client *crowdsec.Client) autodeban.CrowdSecListActiveBans {
	if client == nil {
		return nil
	}
	return client.ListActiveBans
}

// startAutoDeban launches the periodic reputation-triggered early-deban
// scanner (internal/security/autodeban), gated by
// reputation_policy.cloudflare.auto_deban_enabled. It is a no-op if
// lifecycleStore, gate, or cfEnforcer is nil — those are the minimum
// dependencies for the scan to ever recommend a deban (a nil CrowdSec
// checker still runs the scan, but autodeban.CrowdSecListActiveBans fails
// closed — see its doc comment — so no deban is ever a false negative for
// "CrowdSec might still want this IP banned").
func startAutoDeban(ctx context.Context, logger *slog.Logger, cfg *config.Config, gate *reputation.Gate, lifecycleStore banlifecycle.Store, cfEnforcer cfpkg.EnforcementClient, zoneID string, evidenceStore reporting.EvidenceStore, auditJournal journal.JournalStore, trustReg *sectrust.Registry) {
	if cfg == nil || !cfg.ReputationPolicy.Cloudflare.AutoDebanEnabled {
		return
	}
	if lifecycleStore == nil || gate == nil || cfEnforcer == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}

	var crowdsecChecker autodeban.CrowdSecChecker
	if cfg.CrowdSec.DecisionsLog != "" || cfg.CrowdSec.BinPath != "" {
		csClient := crowdsec.NewClientFromConfig(cfg.CrowdSec.BinPath, cfg.CrowdSec.DecisionsLog, cfg.CrowdSec.Timeout)
		crowdsecChecker = crowdsecActiveBansChecker(csClient)
	}

	svcCfg := autodeban.Config{
		Enabled:              true,
		Mode:                 reputation.Mode(cfg.ReputationPolicy.EffectiveMode()),
		NoNewEventsWindow:    24 * time.Hour,
		RecentWAFEventWindow: 24 * time.Hour,
		ZoneID:               zoneID,
	}

	svc := autodeban.NewService(
		lifecycleStore,
		gate,
		&cfCleanupAdapter{client: cfEnforcer},
		crowdsecChecker,
		&autodebanEvidenceAdapter{store: evidenceStore},
		&autodebanJournalAuditSink{journal: auditJournal},
		&autodebanEvidenceWriter{store: evidenceStore},
		trustReg,
		svcCfg,
		logger,
	)

	interval := cfg.ReputationPolicy.Cloudflare.CleanupInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	go func() {
		runAutoDebanScanOnce(ctx, logger, svc)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runAutoDebanScanOnce(ctx, logger, svc)
			}
		}
	}()
}

func runAutoDebanScanOnce(parent context.Context, logger *slog.Logger, svc *autodeban.Service) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	result := svc.Scan(ctx)
	if len(result.Debanned) > 0 || len(result.Errors) > 0 {
		logger.Info("autodeban: scan complete", "considered", result.Considered, "debanned", result.Debanned, "errors", result.Errors)
	} else {
		logger.Debug("autodeban: scan complete", "considered", result.Considered, "excluded", result.Excluded)
	}
}
