package sinks

import (
	"context"
	"fmt"

	"github.com/jm/security-automation-go/internal/betterstack"
	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
)

type BetterStackSink struct {
	client betterstack.IngestClient
}

func NewBetterStack(client betterstack.IngestClient) *BetterStackSink {
	if client == nil {
		return nil
	}
	return &BetterStackSink{client: client}
}

func (s *BetterStackSink) Publish(ctx context.Context, event tmevents.SecurityEvent) error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Send(ctx, betterstack.Event{
		Message:   fmt.Sprintf("%s ip=%s stage=%s propagated=%t", event.Source, event.IP, event.EnforcementStage, event.Propagated),
		Source:    event.Source,
		Level:     event.Severity,
		Timestamp: event.Timestamp,
		Payload: map[string]any{
			"ip":                 event.IP,
			"uri":                event.URI,
			"hostname":           event.Hostname,
			"rule_id":            event.RuleID,
			"abuse_type":         event.AbuseType,
			"risk_score":         event.RiskScore,
			"confidence":         event.Confidence,
			"enforcement_stage":  event.EnforcementStage,
			"propagated":         event.Propagated,
			"abuseipdb_reported": event.AbuseIPDBReported,
			"cloudflare_banned":  event.CloudflareBanned,
			"suppression_reason": event.SuppressionReason,
			"severity":           event.Severity,
			"metadata":           event.Metadata,
		},
	})
}
