package reporting

import (
	"context"
	"time"

	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/security/classifier"
	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
)

type reportAttempt struct {
	report            abmodels.ExecutableReport
	pendingEvidenceID string
}

func (s *Service) prepareReportAttempt(req Request, cls classifier.Classification, comment string) reportAttempt {
	report := buildAggregatedReport(req, cls, s.now())
	return reportAttempt{
		report:            report,
		pendingEvidenceID: decisionEvidenceID(req, cls, "report_pending", s.now()),
	}
}

func (s *Service) reserveAndRecordPending(ctx context.Context, req Request, cls classifier.Classification, comment string, telemetryEvent *tmevents.SecurityEvent, attempt reportAttempt) (Result, bool) {
	if s.reservationStore != nil {
		if existing, ok, err := s.reservationStore.FindPendingByIPAndIdempotencyKey(ctx, req.Event.IP, attempt.report.ExecutionID); err == nil && ok {
			telemetryEvent.SuppressionReason = "report_pending"
			telemetryEvent.Metadata["evidence_id"] = existing.EvidenceID
			_ = s.publish(ctx, *telemetryEvent)
			return Result{
				Classification:    cls,
				Comment:           attempt.report.Comment,
				Suppressed:        true,
				SuppressionReason: "report_pending",
				TelemetryEvent:    *telemetryEvent,
				Report:            &attempt.report,
			}, true
		}
		if err := s.reservationStore.Reserve(ctx, ReportReservation{
			IP:             req.Event.IP,
			Source:         telemetrySource(req.Source),
			IdempotencyKey: attempt.report.ExecutionID,
			EvidenceID:     attempt.pendingEvidenceID,
			Status:         ReportStatusPending,
			ExpiresAt:      s.now().Add(abuseAggregationWindow),
			Report:         attempt.report,
		}); err != nil {
			metrics.AbuseIPDBReportDedupStoreErrorsTotal.Inc()
			telemetryEvent.SuppressionReason = "abuseipdb_report_reservation_failed"
			telemetryEvent.Metadata["reservation_error"] = err.Error()
			evidenceID := s.recordEvidenceWithID(ctx, attempt.pendingEvidenceID, req, cls, attempt.report.Comment, *telemetryEvent, false, true, "abuseipdb_report_reservation_failed")
			if evidenceID != "" {
				telemetryEvent.Metadata["evidence_id"] = evidenceID
			}
			_ = s.publish(ctx, *telemetryEvent)
			return Result{Classification: cls, Comment: attempt.report.Comment, Suppressed: true, SuppressionReason: "abuseipdb_report_reservation_failed", TelemetryEvent: *telemetryEvent}, true
		}
		evidenceID := s.recordEvidenceWithID(ctx, attempt.pendingEvidenceID, req, cls, attempt.report.Comment, *telemetryEvent, false, true, "report_pending")
		if evidenceID != "" {
			telemetryEvent.Metadata["evidence_id"] = evidenceID
		}
		if evidenceID == "" && s.evidenceStore != nil {
			_ = s.reservationStore.MarkStatus(ctx, attempt.pendingEvidenceID, ReportStatusFailed)
			telemetryEvent.SuppressionReason = "abuseipdb_report_evidence_failed"
			_ = s.publish(ctx, *telemetryEvent)
			return Result{
				Classification:    cls,
				Comment:           attempt.report.Comment,
				Suppressed:        true,
				SuppressionReason: "abuseipdb_report_evidence_failed",
				TelemetryEvent:    *telemetryEvent,
				Report:            &attempt.report,
			}, true
		}
		_ = s.publish(ctx, *telemetryEvent)
		return Result{
			Classification:    cls,
			Comment:           attempt.report.Comment,
			Suppressed:        true,
			SuppressionReason: "report_pending",
			TelemetryEvent:    *telemetryEvent,
			Report:            &attempt.report,
		}, true
	}
	evidenceID := s.recordEvidenceWithID(ctx, attempt.pendingEvidenceID, req, cls, attempt.report.Comment, *telemetryEvent, false, false, "report_pending")
	if evidenceID == "" && s.evidenceStore != nil {
		if s.reservationStore != nil {
			_ = s.reservationStore.MarkStatus(ctx, attempt.pendingEvidenceID, ReportStatusFailed)
		}
		telemetryEvent.SuppressionReason = "abuseipdb_report_evidence_failed"
		_ = s.publish(ctx, *telemetryEvent)
		return Result{Classification: cls, Comment: attempt.report.Comment, Suppressed: true, SuppressionReason: "abuseipdb_report_evidence_failed", TelemetryEvent: *telemetryEvent}, true
	}
	return Result{}, false
}

func (s *Service) executeUpstreamReport(ctx context.Context, req Request, cls classifier.Classification, comment string, telemetryEvent *tmevents.SecurityEvent, attempt reportAttempt) (Result, bool, error) {
	if s.reporter == nil {
		return Result{}, false, nil
	}
	if err := s.reporter.Execute(ctx, []abmodels.ExecutableReport{attempt.report}); err != nil {
		telemetryEvent.SuppressionReason = "abuseipdb_report_failed"
		if s.reservationStore != nil {
			_ = s.reservationStore.RecordAttempt(ctx, attempt.pendingEvidenceID, ReportStatusFailed, err.Error(), s.now().Add(5*time.Minute))
		}
		evidenceID := s.recordEvidence(ctx, req, cls, comment, *telemetryEvent, false, true, "abuseipdb_report_failed")
		if evidenceID != "" {
			telemetryEvent.Metadata["evidence_id"] = evidenceID
		}
		_ = s.publish(ctx, *telemetryEvent)
		return Result{
			Classification:    cls,
			Comment:           attempt.report.Comment,
			Suppressed:        true,
			SuppressionReason: "abuseipdb_report_failed",
			TelemetryEvent:    *telemetryEvent,
			Report:            &attempt.report,
		}, true, err
	}
	return Result{}, false, nil
}
