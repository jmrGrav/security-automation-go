package reporting

import (
	"context"
	"strings"
	"sync"
	"time"

	abexec "github.com/jm/security-automation-go/internal/abuseipdb/executor"
	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/classifier"
	"github.com/jm/security-automation-go/internal/security/reportdedup"
	"github.com/jm/security-automation-go/internal/security/trust"
	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

type Request struct {
	Source abuseformat.Source
	Event  classifier.Event
}

type Result struct {
	Classification    classifier.Classification
	Comment           string
	Reported          bool
	Suppressed        bool
	SuppressionReason string
	TelemetryEvent    tmevents.SecurityEvent
	Report            *abmodels.ExecutableReport
}

type Service struct {
	reporter           abexec.Executor
	sink               sinks.Sink
	trust              *trust.Registry
	evidenceStore      EvidenceStore
	reservationStore   ReportReservationStore
	dedupTTL           time.Duration
	reportWindow       time.Duration
	lowConfidence      float64
	dedupStore         reportdedup.Store
	failClosedOnStore  bool
	now                func() time.Time
	mu                 sync.Mutex
	recentFingerprints map[string]time.Time
	ipLocks            map[string]*sync.Mutex
}

func New(reporter abexec.Executor, sink sinks.Sink, registry *trust.Registry, dedupTTL time.Duration) *Service {
	if dedupTTL <= 0 {
		dedupTTL = 15 * time.Minute
	}
	return &Service{
		reporter:           reporter,
		sink:               sink,
		trust:              registry,
		dedupTTL:           dedupTTL,
		reportWindow:       24 * time.Hour,
		lowConfidence:      0.70,
		failClosedOnStore:  true,
		now:                func() time.Time { return time.Now().UTC() },
		recentFingerprints: make(map[string]time.Time),
		ipLocks:            make(map[string]*sync.Mutex),
	}
}

func (s *Service) SetReportDedupStore(store reportdedup.Store) {
	s.dedupStore = store
}

func (s *Service) SetEvidenceStore(store EvidenceStore) {
	s.evidenceStore = store
}

func (s *Service) SetReportReservationStore(store ReportReservationStore) {
	s.reservationStore = store
}

func (s *Service) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func (s *Service) SetReportWindow(window time.Duration) {
	if window > 0 {
		s.reportWindow = window
	}
}

func (s *Service) SetFailClosedOnStoreError(enabled bool) {
	s.failClosedOnStore = enabled
}

func (s *Service) Process(ctx context.Context, req Request) (Result, error) {
	prepared := s.prepareDecision(req)
	cls := prepared.classification
	comment := prepared.comment
	telemetryEvent := prepared.telemetry

	suppressionReason := s.suppressionReason(req, cls)
	if suppressionReason != "" {
		if req.Source == abuseformat.SourceCloudflareWAF && suppressionReason == "low_confidence" {
			metrics.CloudflareEventsSuppressedLowConfidenceTotal.Inc()
		}
		telemetryEvent.SuppressionReason = suppressionReason
		evidenceID := s.recordEvidence(ctx, req, cls, comment, telemetryEvent, false, true, suppressionReason)
		if evidenceID != "" {
			telemetryEvent.Metadata["evidence_id"] = evidenceID
		}
		_ = s.publish(ctx, telemetryEvent)
		return Result{
			Classification:    cls,
			Comment:           comment,
			Suppressed:        true,
			SuppressionReason: suppressionReason,
			TelemetryEvent:    telemetryEvent,
		}, nil
	}

	unlock := s.lockIP(strings.TrimSpace(req.Event.IP))
	defer unlock()

	if recentResult, handled, err := s.enforceRecentReportWindow(ctx, req, cls, telemetryEvent, comment); handled || err != nil {
		return recentResult, err
	}

	attempt := s.prepareReportAttempt(req, cls, comment)
	if result, handled := s.reserveAndRecordPending(ctx, req, cls, comment, &telemetryEvent, attempt); handled {
		return result, nil
	}
	if result, handled, err := s.executeUpstreamReport(ctx, req, cls, comment, &telemetryEvent, attempt); handled || err != nil {
		return result, err
	}

	recordReportMetrics(req.Source, cls)
	metrics.AbuseIPDBReportsSentTotal.Inc()
	telemetryEvent.AbuseIPDBReported = true
	successEvidenceID := s.recordEvidence(ctx, req, cls, comment, telemetryEvent, true, false, "")
	if successEvidenceID == "" {
		successEvidenceID = attempt.pendingEvidenceID
	}
	telemetryEvent.Metadata["evidence_id"] = successEvidenceID
	if err := s.markReported(ctx, req.Event.IP, successEvidenceID); err != nil {
		metrics.AbuseIPDBReportDedupStoreErrorsTotal.Inc()
		telemetryEvent.Metadata["dedup_store_mark_error"] = err.Error()
		if s.reservationStore != nil {
			_ = s.reservationStore.RecordAttempt(ctx, attempt.pendingEvidenceID, ReportStatusReportedDedupFailed, err.Error(), time.Time{})
		}
	} else if s.reservationStore != nil {
		_ = s.reservationStore.MarkStatus(ctx, attempt.pendingEvidenceID, ReportStatusReported)
	}
	_ = s.publish(ctx, telemetryEvent)

	return Result{
		Classification: cls,
		Comment:        comment,
		Reported:       true,
		TelemetryEvent: telemetryEvent,
		Report:         &attempt.report,
	}, nil
}
