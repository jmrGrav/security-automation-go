package cloudflareevent

import (
	"context"
	"time"

	cfmodels "github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/services/reporting"
	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
)

type Source interface {
	ListWAFEventsSince(ctx context.Context, zoneID string, since time.Time) ([]cfmodels.WAFEvent, error)
}

type Service struct {
	source    Source
	reporting *reporting.Service
}

type SuppressionBreakdown struct {
	ProtectedTarget  int
	BenignSignal     int
	LowConfidence    int
	NoCategories     int
	DuplicateReport  int
	RecentlyReported int
	DedupeStoreError int
	MalformedEvent   int
	Other            int
}

// MaliciousEvent is a stripped-down record of a non-benign classified event,
// used by the auto-ban evaluator to update the burst counter.
type MaliciousEvent struct {
	IP        string
	AbuseType string
	Timestamp time.Time
	RayID     string
}

type ProcessingReport struct {
	Fetched       int
	Classified    int
	Reported      int
	Suppressed    int
	Breakdown     SuppressionBreakdown
	HighWatermark time.Time
	// MaliciousEvents holds non-benign, non-protected events from this batch.
	// Only populated when the event passes the reporting pipeline without a
	// benign_signal or protected_target suppression.
	MaliciousEvents []MaliciousEvent
}

func (r *ProcessingReport) addSuppression(reason string) {
	switch reason {
	case "protected_target":
		r.Breakdown.ProtectedTarget++
	case "benign_signal":
		r.Breakdown.BenignSignal++
	case "low_confidence":
		r.Breakdown.LowConfidence++
	case "no_abuse_categories":
		r.Breakdown.NoCategories++
	case "duplicate_report":
		r.Breakdown.DuplicateReport++
	case "abuseipdb_recently_reported":
		r.Breakdown.RecentlyReported++
	case "abuseipdb_dedup_store_error":
		r.Breakdown.DedupeStoreError++
	case "malformed_event":
		r.Breakdown.MalformedEvent++
	default:
		r.Breakdown.Other++
	}
}

func NewService(source Source, reportingService *reporting.Service) *Service {
	return &Service{
		source:    source,
		reporting: reportingService,
	}
}

func (s *Service) ProcessSince(ctx context.Context, zoneID string, since time.Time) (ProcessingReport, error) {
	var report ProcessingReport

	if s == nil || s.source == nil || s.reporting == nil {
		return report, nil
	}

	events, err := s.source.ListWAFEventsSince(ctx, zoneID, since)
	if err != nil {
		return report, err
	}
	report.Fetched = len(events)

	for _, event := range events {
		if event.Datetime.After(report.HighWatermark) {
			report.HighWatermark = event.Datetime.UTC()
		}
		normalized, err := Normalize(RawEvent{
			IP:                 event.ClientIP,
			URI:                joinPathAndQuery(event.ClientRequestPath, event.ClientRequestQuery),
			Hostname:           event.Host,
			UserAgent:          event.UserAgent,
			Action:             event.Action,
			HTTPMethod:         event.HTTPMethod,
			RuleID:             event.RuleID,
			RulesetID:          event.RulesetID,
			RuleName:           event.Description,
			Source:             event.Source,
			Timestamp:          event.Datetime,
			RayID:              event.RayName,
			CountryName:        event.CountryName,
			ASNDescription:     event.ASNDescription,
			EdgeResponseStatus: event.EdgeResponseStatus,
			Hits:               1,
			WindowSec:          300,
		})
		if err != nil {
			report.Suppressed++
			report.addSuppression("malformed_event")
			metrics.CloudflareWAFMalformedEventsTotal.Inc()
			s.reporting.Observe(ctx, tmevents.SecurityEvent{
				Timestamp:         time.Now().UTC(),
				Source:            "cloudflare_waf",
				AbuseType:         "malformed_event",
				EnforcementStage:  "suppressed",
				Severity:          "warning",
				SuppressionReason: "malformed_event",
				Metadata: map[string]any{
					"error":       err.Error(),
					"rule_id":     event.RuleID,
					"description": event.Description,
				},
			})
			continue
		}

		result, err := s.reporting.Process(ctx, reporting.Request{
			Source: abuseformat.SourceCloudflareWAF,
			Event:  normalized,
		})
		report.Classified++
		if err != nil {
			return report, err
		}
		if result.Reported {
			report.Reported++
		}
		if result.Suppressed {
			report.Suppressed++
			report.addSuppression(result.SuppressionReason)
		}
		// Track malicious (non-benign, non-protected) events for burst-ban evaluation.
		// Skip benign signals and protected targets — those must never increment the counter.
		if result.SuppressionReason != "benign_signal" && result.SuppressionReason != "protected_target" {
			if !isBenignAbuseType(result.Classification.AbuseType) {
				report.MaliciousEvents = append(report.MaliciousEvents, MaliciousEvent{
					IP:        normalized.IP,
					AbuseType: result.Classification.AbuseType,
					Timestamp: normalized.Timestamp,
					RayID:     normalized.RayID,
				})
			}
		}
	}

	return report, nil
}

func isBenignAbuseType(abuseType string) bool {
	return abuseType == "benign_bootstrap" || abuseType == "benign_probe" || abuseType == ""
}

func joinPathAndQuery(path string, query string) string {
	if query == "" {
		return path
	}
	return path + "?" + query
}
