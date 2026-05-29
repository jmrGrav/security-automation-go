package sinks

import (
	"context"

	"github.com/jm/security-automation-go/internal/observability/metrics"
	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
)

type PrometheusSink struct{}

func NewPrometheus() *PrometheusSink { return &PrometheusSink{} }

func (s *PrometheusSink) Publish(_ context.Context, event tmevents.SecurityEvent) error {
	metrics.SecurityRiskScore.Observe(float64(event.RiskScore))
	switch event.AbuseType {
	case "benign_bootstrap", "benign_probe":
		metrics.SecurityBenignProbeTotal.Inc()
	}
	if event.SuppressionReason != "" {
		metrics.SecurityFalsePositiveSuppressedTotal.Inc()
		metrics.SecurityLowSignalSuppressedTotal.Inc()
	}
	switch event.EnforcementStage {
	case "soft_mitigation":
		metrics.SecuritySoftMitigationTotal.Inc()
		metrics.SecurityProgressiveEscalationTotal.Inc()
	case "local_block":
		metrics.SecurityProgressiveEscalationTotal.Inc()
	case "propagable_ban":
		metrics.SecurityProgressiveEscalationTotal.Inc()
		metrics.SecurityHardBanAllowedTotal.Inc()
	}
	return nil
}
