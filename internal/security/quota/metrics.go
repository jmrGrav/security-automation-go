package quota

import (
	"github.com/jm/security-automation-go/internal/observability/metrics"
)

func updateMetrics(obs Observation, transition Transition) {
	if obs.Provider == "" {
		return
	}
	if obs.PercentKnown {
		metrics.ProviderQuotaRemainingPercent.WithLabelValues(obs.Provider).Set(obs.RemainingPercent)
	}
	metrics.ProviderQuotaState.WithLabelValues(obs.Provider).Set(quotaStateMetricValue(obs.State))

	switch {
	case transition.Current == Exhausted && transition.Previous != Exhausted:
		metrics.ProviderAutoDisableTotal.WithLabelValues(obs.Provider).Inc()
	case transition.Current == Throttled && transition.Previous != Throttled:
		metrics.ProviderAutoThrottleTotal.WithLabelValues(obs.Provider).Inc()
	case isRecoveredQuota(transition.Previous, transition.Current):
		metrics.ProviderAutoReenableTotal.WithLabelValues(obs.Provider).Inc()
	}
}

func quotaStateMetricValue(state State) float64 {
	switch state {
	case Normal:
		return 0
	case Warning:
		return 1
	case Throttled:
		return 2
	case Exhausted:
		return 3
	default:
		return 4
	}
}

func isRecoveredQuota(previous, current State) bool {
	if previous == Exhausted || previous == Throttled {
		return current == Warning || current == Normal
	}
	return false
}

func RecordRefreshFailure(provider string) {
	if provider == "" {
		return
	}
	metrics.ProviderQuotaRefreshFailuresTotal.WithLabelValues(provider).Inc()
}
