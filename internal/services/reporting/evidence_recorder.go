package reporting

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/security/classifier"
	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
)

func (s *Service) recordEvidence(ctx context.Context, req Request, cls classifier.Classification, comment string, telemetryEvent tmevents.SecurityEvent, reported bool, suppressed bool, suppressionReason string) string {
	return s.recordEvidenceWithID(ctx, decisionEvidenceID(req, cls, suppressionReason, s.now()), req, cls, comment, telemetryEvent, reported, suppressed, suppressionReason)
}

func (s *Service) recordEvidenceWithID(ctx context.Context, evidenceID string, req Request, cls classifier.Classification, comment string, telemetryEvent tmevents.SecurityEvent, reported bool, suppressed bool, suppressionReason string) string {
	if s == nil || s.evidenceStore == nil {
		return ""
	}
	lastReportedAt, nextAllowedAt := evidenceWindowFromMetadata(telemetryEvent.Metadata)
	decision := decisionKind(reported, suppressed)
	if suppressionReason == "report_pending" {
		decision = "report_pending"
	}
	ev := DecisionEvidence{
		EvidenceID:        evidenceID,
		Timestamp:         s.now(),
		Source:            telemetrySource(req.Source),
		IP:                req.Event.IP,
		Hostname:          req.Event.Hostname,
		URI:               req.Event.URI,
		URIs:              eventURIs(req.Event),
		RuleID:            req.Event.RuleID,
		AbuseType:         cls.AbuseType,
		Categories:        append([]string(nil), cls.Categories...),
		RiskScore:         cls.RiskScore,
		Confidence:        cls.Confidence,
		EnforcementStage:  cls.EnforcementStage,
		Decision:          decision,
		Comment:           comment,
		Reported:          reported,
		Suppressed:        suppressed,
		SuppressionReason: suppressionReason,
		AbuseIPDBReported: reported,
		CloudflareBanned:  telemetryEvent.CloudflareBanned,
		IdempotencyKey:    executionID(req, cls),
		DedupKey:          fingerprint(req, cls),
		LastReportedAt:    lastReportedAt,
		NextAllowedAt:     nextAllowedAt,
		InputHash:         evidenceInputHash(req),
		DecisionHash:      evidenceDecisionHash(comment, cls, decision, suppressionReason),
		ClassifierVersion: ClassifierVersion,
		FormatterVersion:  FormatterVersion,
		PolicyVersion:     PolicyVersion,
		NormalizedEvent:   req.Event,
		WAFRef:            req.Event.Ref,
		Metadata: map[string]any{
			"source_name":        string(req.Source),
			"replay_evidence":    append([]string(nil), cls.Evidence...),
			"telemetry_metadata": copyMetadata(telemetryEvent.Metadata),
		},
	}
	if err := s.evidenceStore.Append(ctx, ev); err != nil {
		metrics.EvidenceWriteFailuresTotal.Inc()
		telemetryEvent.Metadata["evidence_store_error"] = err.Error()
		return ""
	}
	return evidenceID
}

func (s *Service) recordObservedEvidence(ctx context.Context, event tmevents.SecurityEvent) string {
	if s == nil || s.evidenceStore == nil {
		return ""
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = s.now()
	}
	evidenceID := observedEvidenceID(event)
	ev := DecisionEvidence{
		EvidenceID:        evidenceID,
		Timestamp:         event.Timestamp.UTC(),
		Source:            event.Source,
		IP:                event.IP,
		Hostname:          event.Hostname,
		URI:               event.URI,
		RuleID:            event.RuleID,
		AbuseType:         event.AbuseType,
		RiskScore:         event.RiskScore,
		Confidence:        event.Confidence,
		EnforcementStage:  event.EnforcementStage,
		Decision:          "observed",
		Reported:          false,
		Suppressed:        event.SuppressionReason != "",
		SuppressionReason: event.SuppressionReason,
		AbuseIPDBReported: event.AbuseIPDBReported,
		CloudflareBanned:  event.CloudflareBanned,
		InputHash:         observedHash(event, "input"),
		DecisionHash:      observedHash(event, "decision"),
		ClassifierVersion: ClassifierVersion,
		FormatterVersion:  FormatterVersion,
		PolicyVersion:     PolicyVersion,
		Metadata: map[string]any{
			"telemetry_metadata": copyMetadata(event.Metadata),
		},
	}
	if err := s.evidenceStore.Append(ctx, ev); err != nil {
		metrics.EvidenceWriteFailuresTotal.Inc()
		if event.Metadata != nil {
			event.Metadata["evidence_store_error"] = err.Error()
		}
		return ""
	}
	return evidenceID
}

func copyMetadata(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func evidenceWindowFromMetadata(metadata map[string]any) (time.Time, time.Time) {
	if len(metadata) == 0 {
		return time.Time{}, time.Time{}
	}
	var lastReportedAt time.Time
	var nextAllowedAt time.Time
	if raw, ok := metadata["last_reported_at"].(string); ok {
		if ts, err := time.Parse(time.RFC3339, raw); err == nil {
			lastReportedAt = ts.UTC()
		}
	}
	if raw, ok := metadata["next_allowed_at"].(string); ok {
		if ts, err := time.Parse(time.RFC3339, raw); err == nil {
			nextAllowedAt = ts.UTC()
		}
	}
	return lastReportedAt, nextAllowedAt
}

func observedEvidenceID(event tmevents.SecurityEvent) string {
	sum := sha256.Sum256([]byte(
		event.Source + "|" +
			event.IP + "|" +
			event.URI + "|" +
			event.RuleID + "|" +
			event.AbuseType + "|" +
			event.SuppressionReason + "|" +
			event.Timestamp.UTC().Format(time.RFC3339Nano),
	))
	return "observed-ev-" + hex.EncodeToString(sum[:8])
}

func observedHash(event tmevents.SecurityEvent, salt string) string {
	sum := sha256.Sum256([]byte(
		salt + "|" +
			event.Source + "|" +
			event.IP + "|" +
			event.URI + "|" +
			event.Hostname + "|" +
			event.RuleID + "|" +
			event.AbuseType + "|" +
			event.EnforcementStage + "|" +
			event.SuppressionReason,
	))
	return hex.EncodeToString(sum[:])
}
