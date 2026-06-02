package reporting

import (
	"context"
	"errors"
	"net/netip"
	"time"

	abexec "github.com/jm/security-automation-go/internal/abuseipdb/executor"
	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/security/reportdedup"
	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

type OutboxWorkerConfig struct {
	Limit        int
	RetryBackoff time.Duration
	Interval     time.Duration
	ClaimLease   time.Duration
	Clock        func() time.Time
	LeaseGuard   OutboxLeaseGuard
}

type OutboxLeaseGuard interface {
	ValidateOutboxItem(ctx context.Context, item ReportOutboxItem) error
}

type OutboxWorker struct {
	store        ReportReservationStore
	reporter     abexec.Executor
	dedupStore   reportdedup.Store
	evidence     EvidenceStore
	sink         sinks.Sink
	limit        int
	retryBackoff time.Duration
	interval     time.Duration
	claimLease   time.Duration
	now          func() time.Time
	leaseGuard   OutboxLeaseGuard
}

func NewOutboxWorker(store ReportReservationStore, reporter abexec.Executor, dedupStore reportdedup.Store, evidence EvidenceStore, sink sinks.Sink, cfg OutboxWorkerConfig) *OutboxWorker {
	if cfg.Limit <= 0 {
		cfg.Limit = 50
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 5 * time.Minute
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	if cfg.ClaimLease <= 0 {
		cfg.ClaimLease = 30 * time.Second
	}
	return &OutboxWorker{
		store:        store,
		reporter:     reporter,
		dedupStore:   dedupStore,
		evidence:     evidence,
		sink:         sink,
		limit:        cfg.Limit,
		retryBackoff: cfg.RetryBackoff,
		interval:     cfg.Interval,
		claimLease:   cfg.ClaimLease,
		now:          cfg.Clock,
		leaseGuard:   cfg.LeaseGuard,
	}
}

func (w *OutboxWorker) SetLeaseGuard(guard OutboxLeaseGuard) {
	w.leaseGuard = guard
}

func (w *OutboxWorker) HasLeaseGuard() bool {
	return w != nil && w.leaseGuard != nil
}

func (w *OutboxWorker) ProcessOnce(ctx context.Context) (int, error) {
	if w == nil || w.store == nil || w.reporter == nil {
		return 0, nil
	}
	items, err := w.store.ClaimRetryable(ctx, w.now(), w.limit, w.now().Add(w.claimLease))
	if err != nil {
		metrics.AbuseIPDBReportDedupStoreErrorsTotal.Inc()
		return 0, err
	}
	metrics.AbuseIPDBOutboxPendingTotal.Add(float64(len(items)))
	var firstErr error
	var processed int
	for _, item := range items {
		if ctx.Err() != nil {
			return processed, ctx.Err()
		}
		if w.leaseGuard != nil {
			if err := w.leaseGuard.ValidateOutboxItem(ctx, item); err != nil {
				w.recordOutboxEvidence(ctx, item, false, true, "outbox_lease_guard_refused", err.Error())
				if firstErr == nil {
					firstErr = err
				}
				return processed, err
			}
		}
		if err := w.processItem(ctx, item); err != nil && firstErr == nil {
			firstErr = err
		}
		processed++
	}
	return processed, firstErr
}

func (w *OutboxWorker) Run(ctx context.Context) error {
	if w == nil {
		return nil
	}
	if w.interval <= 0 {
		_, err := w.ProcessOnce(ctx)
		return err
	}
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		if _, err := w.ProcessOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			// Retry failures are recorded per item; the loop remains fail-open for telemetry/reporting.
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (w *OutboxWorker) processItem(ctx context.Context, item ReportOutboxItem) error {
	report := item.Reservation.Report
	if report.IP == "" {
		report.IP = item.Reservation.IP
	}
	if err := w.reporter.Execute(ctx, []abmodels.ExecutableReport{report}); err != nil {
		_ = w.store.RecordAttempt(ctx, item.Reservation.EvidenceID, ReportStatusFailed, err.Error(), w.now().Add(w.retryBackoff))
		metrics.AbuseIPDBOutboxFailedTotal.Inc()
		w.recordOutboxEvidence(ctx, item, false, true, "abuseipdb_outbox_retry_failed", err.Error())
		return err
	}
	if err := w.markDedup(ctx, item); err != nil {
		metrics.AbuseIPDBReportDedupStoreErrorsTotal.Inc()
		_ = w.store.RecordAttempt(ctx, item.Reservation.EvidenceID, ReportStatusReportedDedupFailed, err.Error(), time.Time{})
		metrics.AbuseIPDBOutboxFailedTotal.Inc()
		w.recordOutboxEvidence(ctx, item, true, true, "abuseipdb_outbox_dedup_mark_failed", err.Error())
		return err
	}
	if err := w.store.MarkStatus(ctx, item.Reservation.EvidenceID, ReportStatusReported); err != nil {
		metrics.AbuseIPDBReportDedupStoreErrorsTotal.Inc()
		metrics.AbuseIPDBOutboxFailedTotal.Inc()
		w.recordOutboxEvidence(ctx, item, true, true, "abuseipdb_outbox_status_failed", err.Error())
		return err
	}
	metrics.AbuseIPDBReportsSentTotal.Inc()
	metrics.AbuseIPDBOutboxReportedTotal.Inc()
	w.recordOutboxEvidence(ctx, item, true, false, "", "")
	return nil
}

func (w *OutboxWorker) markDedup(ctx context.Context, item ReportOutboxItem) error {
	if w.dedupStore == nil {
		return nil
	}
	addr, err := netip.ParseAddr(item.Reservation.IP)
	if err != nil {
		return err
	}
	return w.dedupStore.MarkReported(ctx, addr, w.now(), item.Reservation.EvidenceID)
}

func (w *OutboxWorker) recordOutboxEvidence(ctx context.Context, item ReportOutboxItem, reported bool, suppressed bool, reason string, errText string) {
	now := w.now()
	event := tmevents.SecurityEvent{
		Timestamp:         now,
		Source:            item.Reservation.Source,
		IP:                item.Reservation.IP,
		AbuseIPDBReported: reported,
		SuppressionReason: reason,
		Severity:          "warning",
		Metadata: map[string]any{
			"outbox_evidence_id": item.Reservation.EvidenceID,
			"idempotency_key":    item.Reservation.IdempotencyKey,
			"attempt_count":      item.AttemptCount + 1,
		},
	}
	if reason == "" {
		event.AbuseType = "abuseipdb_outbox_report_succeeded"
		event.EnforcementStage = "reported"
		event.Severity = "info"
	} else {
		event.AbuseType = reason
		event.EnforcementStage = "suppressed"
		event.Metadata["error"] = errText
	}
	if w.evidence != nil {
		_ = w.evidence.Append(ctx, DecisionEvidence{
			EvidenceID:        item.Reservation.EvidenceID + "-outbox-" + now.UTC().Format("20060102T150405.000000000Z"),
			Timestamp:         now,
			Source:            item.Reservation.Source,
			IP:                item.Reservation.IP,
			Decision:          event.EnforcementStage,
			Reported:          reported,
			Suppressed:        suppressed,
			SuppressionReason: reason,
			AbuseIPDBReported: reported,
			IdempotencyKey:    item.Reservation.IdempotencyKey,
			Metadata:          event.Metadata,
		})
	}
	if w.sink != nil {
		_ = w.sink.Publish(ctx, event)
	}
}
