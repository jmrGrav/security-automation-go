package reporting

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	abexec "github.com/jm/security-automation-go/internal/abuseipdb/executor"
	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/classifier"
	"github.com/jm/security-automation-go/internal/security/enrichment/spamhaus"
	"github.com/jm/security-automation-go/internal/security/reportdedup"
	"github.com/jm/security-automation-go/internal/security/reputation"
	"github.com/jm/security-automation-go/internal/security/trust"
	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

type Request struct {
	Source abuseformat.Source
	Event  classifier.Event

	// EvidenceOnly forces this event to be recorded as Evidence/Timeline
	// without ever submitting to AbuseIPDB, Spamhaus, or feeding auto-ban.
	// Used for WAF detections that have no corroborating ban decision yet —
	// keeps the pipeline evidence-first per the WAF integration constraints.
	EvidenceOnly bool
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
	reporter          abexec.Executor
	sink              sinks.Sink
	trust             *trust.Registry
	evidenceStore     EvidenceStore
	reservationStore  ReportReservationStore
	dedupTTL          time.Duration
	reportWindow      time.Duration
	lowConfidence     float64
	dedupStore        reportdedup.Store
	failClosedOnStore bool
	now               func() time.Time
	gate              *decisionGate
	spamhausClient    spamhaus.Client
	spamhausDedup     *spamhausIPDedup
	logger            *slog.Logger

	// reputationGate, when set, is consulted after the pre-existing
	// suppressionReason() short-circuit and before the report is reserved /
	// submitted. It never replaces the existing local-confidence gate — it
	// is an additional, later checkpoint. Fail-open: if SetReputationGate is
	// never called, this is nil and Process behaves exactly as before.
	reputationGate ReputationGate
}

// ReputationGate is the subset of *reputation.Gate the reporting service
// needs. Kept as an interface so tests can fake it without standing up a
// real enrichment.Service.
type ReputationGate interface {
	EvaluateReport(ctx context.Context, ip string, local reputation.LocalSignal) reputation.Decision
}

func New(reporter abexec.Executor, sink sinks.Sink, registry *trust.Registry, dedupTTL time.Duration) *Service {
	if dedupTTL <= 0 {
		dedupTTL = 15 * time.Minute
	}
	now := func() time.Time { return time.Now().UTC() }
	return &Service{
		reporter:          reporter,
		sink:              sink,
		trust:             registry,
		dedupTTL:          dedupTTL,
		reportWindow:      24 * time.Hour,
		lowConfidence:     0.70,
		failClosedOnStore: true,
		now:               now,
		gate:              newDecisionGate(dedupTTL, now),
		spamhausDedup:     newSpamhausIPDedup(24*time.Hour, now),
		logger:            slog.Default(),
	}
}

// SetSpamhausClient wires an independent Spamhaus Submit reporter.
// A nil client disables Spamhaus submission (fail-open).
func (s *Service) SetSpamhausClient(client spamhaus.Client) {
	s.spamhausClient = client
}

func (s *Service) SetReportDedupStore(store reportdedup.Store) {
	s.dedupStore = store
}

func (s *Service) SetEvidenceStore(store EvidenceStore) {
	s.evidenceStore = store
}

// SetReputationGate wires the cross-provider reputation gate
// (internal/security/reputation) into Process(). A nil gate (the default)
// disables this checkpoint entirely — pre-existing suppression/report
// behavior is unaffected.
func (s *Service) SetReputationGate(gate ReputationGate) {
	s.reputationGate = gate
}

func (s *Service) SetReportReservationStore(store ReportReservationStore) {
	s.reservationStore = store
}

func (s *Service) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
		if s.gate != nil {
			s.gate.setClock(now)
		}
		if s.spamhausDedup != nil {
			s.spamhausDedup.setClock(now)
		}
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

	if req.EvidenceOnly {
		return s.handleSuppressedDecision(ctx, req, cls, comment, telemetryEvent, "waf_evidence_only")
	}

	suppressionReason := s.suppressionReason(req, cls)
	if suppressionReason != "" {
		return s.handleSuppressedDecision(ctx, req, cls, comment, telemetryEvent, suppressionReason)
	}

	// Reputation gate: an additional, later checkpoint consulted only after
	// the pre-existing local-confidence suppression above has already
	// allowed this report through. Fail-open by construction: any
	// gate/provider error surfaces as reputation.ActionAllow (see
	// EvaluateReport callers / Evaluate's provider_unavailable branch), so a
	// gate failure can never crash or stall the outbox — at worst it falls
	// back to pre-gate behavior. In shadow mode the gate's decision is
	// observed but never applied: this is enforced by the gate itself
	// (Decision.Shadow) rather than by hiding the call here.
	if s.reputationGate != nil {
		decision := s.reputationGate.EvaluateReport(ctx, req.Event.IP, reputationLocalSignal(cls))
		if !decision.Shadow && !decision.AllowReport {
			return s.handleSuppressedDecision(ctx, req, cls, comment, telemetryEvent, decision.Reason)
		}
		if s.logger != nil {
			s.logger.Debug("reputation gate decision",
				"ip", req.Event.IP, "action", decision.Action, "reason", decision.Reason,
				"shadow", decision.Shadow, "provider_unavailable", decision.ProviderUnavailable)
		}
	}

	// Spamhaus submit: independent from AbuseIPDB, fail-open, own 24h dedup per IP.
	s.submitToSpamhaus(ctx, req.Event.IP, cls.AbuseType)

	unlock := s.gate.lockIP(strings.TrimSpace(req.Event.IP))
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

	return s.finalizeReportedDecision(ctx, req, cls, comment, telemetryEvent, attempt), nil
}

func (s *Service) handleSuppressedDecision(ctx context.Context, req Request, cls classifier.Classification, comment string, telemetryEvent tmevents.SecurityEvent, suppressionReason string) (Result, error) {
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

func (s *Service) finalizeReportedDecision(ctx context.Context, req Request, cls classifier.Classification, comment string, telemetryEvent tmevents.SecurityEvent, attempt reportAttempt) Result {
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
	}
}

func (s *Service) submitToSpamhaus(ctx context.Context, rawIP string, reason string) {
	if s.spamhausClient == nil {
		return
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return
	}
	if s.spamhausDedup != nil && s.spamhausDedup.markSeen(ip.String()) {
		metrics.SpamhausSubmitDedupTotal.Inc()
		return
	}
	if err := s.spamhausClient.Report(ctx, ip, reason); err != nil {
		metrics.SpamhausSubmitFailuresTotal.Inc()
		if s.logger != nil {
			s.logger.Warn("spamhaus submit failed (fail-open)", "ip", rawIP, "error", err)
		}
		return
	}
	metrics.SpamhausSubmitTotal.Inc()
}
