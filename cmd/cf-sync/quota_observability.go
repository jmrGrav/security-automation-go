package main

import (
	"fmt"
	"time"

	crowdmodels "github.com/jm/security-automation-go/internal/crowdsec/models"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	runmodels "github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/security/quota"
)

func configureQuotaObservability(j journal.JournalStore) {
	if j == nil {
		quota.ResetTransitionHook()
		return
	}
	quota.SetTransitionHook(func(obs quota.Observation, transition quota.Transition) {
		action, ok := quotaTransitionAction(transition)
		if !ok {
			return
		}

		metadata := map[string]interface{}{
			"provider":          obs.Provider,
			"plan":              obs.Plan,
			"quota_source":      obs.QuotaSource,
			"previous_state":    string(transition.Previous),
			"current_state":     string(transition.Current),
			"remaining_known":   obs.RemainingKnown,
			"remaining_percent": obs.RemainingPercent,
			"observed_at":       obs.ObservedAt.UTC().Format(time.RFC3339Nano),
		}
		if obs.LimitKnown {
			metadata["quota_limit"] = obs.Limit
		}
		if obs.UsedKnown {
			metadata["quota_used"] = obs.Used
		}
		if obs.RemainingKnown {
			metadata["quota_remaining"] = obs.Remaining
		}
		if obs.ResetKnown {
			metadata["quota_reset_at"] = obs.ResetAt.UTC().Format(time.RFC3339Nano)
		}

		_ = j.Append(runmodels.AuditEvent{
			Timestamp: obs.ObservedAt.UTC(),
			Status:    string(transition.Current),
			Action:    crowdmodels.ActionType(action),
			Target:    obs.Provider,
			Metadata:  metadata,
		})
	})
}

func quotaTransitionAction(transition quota.Transition) (string, bool) {
	switch transition.Current {
	case quota.Warning:
		return "provider_quota_warning", transition.Previous != quota.Warning
	case quota.Throttled:
		return "provider_quota_throttled", transition.Previous != quota.Throttled
	case quota.Exhausted:
		return "provider_quota_exhausted", transition.Previous != quota.Exhausted
	case quota.Normal:
		if transition.Previous == quota.Warning || transition.Previous == quota.Throttled || transition.Previous == quota.Exhausted {
			return "provider_quota_recovered", true
		}
		return "", false
	default:
		return "", false
	}
}

func quotaTransitionSummary(obs quota.Observation, transition quota.Transition) string {
	return fmt.Sprintf("%s:%s->%s", obs.Provider, transition.Previous, transition.Current)
}
