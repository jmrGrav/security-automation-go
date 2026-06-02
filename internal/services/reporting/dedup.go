package reporting

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/security/classifier"
	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
)

func (s *Service) enforceRecentReportWindow(ctx context.Context, req Request, cls classifier.Classification, telemetryEvent tmevents.SecurityEvent, comment string) (Result, bool, error) {
	if s == nil || s.dedupStore == nil {
		return Result{}, false, nil
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(req.Event.IP))
	if err != nil {
		return Result{}, false, nil
	}

	lastReportedAt, found, err := s.dedupStore.LastReportedAt(ctx, ip)
	if err != nil {
		metrics.AbuseIPDBReportDedupStoreErrorsTotal.Inc()
		if s.failClosedOnStore {
			telemetryEvent.SuppressionReason = "abuseipdb_dedup_store_error"
			telemetryEvent.Metadata["canonical_comment"] = comment
			telemetryEvent.Metadata["dedup_store_error"] = err.Error()
			evidenceID := s.recordEvidence(ctx, req, cls, comment, telemetryEvent, false, true, "abuseipdb_dedup_store_error")
			if evidenceID != "" {
				telemetryEvent.Metadata["evidence_id"] = evidenceID
			}
			_ = s.publish(ctx, telemetryEvent)
			return Result{
				Classification:    cls,
				Comment:           comment,
				Suppressed:        true,
				SuppressionReason: "abuseipdb_dedup_store_error",
				TelemetryEvent:    telemetryEvent,
			}, true, nil
		}
		return Result{}, false, nil
	}
	if !found {
		return Result{}, false, nil
	}

	age := s.now().Sub(lastReportedAt)
	if age < 0 {
		age = 0
	}
	metrics.AbuseIPDBReportAgeSeconds.Observe(age.Seconds())
	if age >= s.reportWindow {
		return Result{}, false, nil
	}

	nextAllowed := lastReportedAt.Add(s.reportWindow)
	metrics.AbuseIPDBReportsSuppressedRecentTotal.Inc()
	telemetryEvent.SuppressionReason = "abuseipdb_recently_reported"
	telemetryEvent.Metadata["event"] = "abuseipdb_report_suppressed"
	telemetryEvent.Metadata["last_reported_at"] = lastReportedAt.UTC().Format(time.RFC3339)
	telemetryEvent.Metadata["next_allowed_at"] = nextAllowed.UTC().Format(time.RFC3339)
	evidenceID := s.recordEvidence(ctx, req, cls, comment, telemetryEvent, false, true, "abuseipdb_recently_reported")
	if evidenceID != "" {
		telemetryEvent.Metadata["evidence_id"] = evidenceID
	}
	_ = s.publish(ctx, telemetryEvent)
	return Result{
		Classification:    cls,
		Comment:           comment,
		Suppressed:        true,
		SuppressionReason: "abuseipdb_recently_reported",
		TelemetryEvent:    telemetryEvent,
	}, true, nil
}

func (s *Service) isProtected(ip string) bool {
	if s == nil || s.trust == nil {
		return false
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		return false
	}
	return len(s.trust.MatchIP(ip)) > 0
}

func (s *Service) markReported(ctx context.Context, ip string, evidenceID string) error {
	if s == nil || s.dedupStore == nil {
		return nil
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return nil
	}
	return s.dedupStore.MarkReported(ctx, addr, s.now(), evidenceID)
}
