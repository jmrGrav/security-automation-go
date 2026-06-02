package main

import (
	"testing"

	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/security/quota"
)

type memoryQuotaJournal struct {
	events []models.AuditEvent
}

func (m *memoryQuotaJournal) Append(event models.AuditEvent) error {
	m.events = append(m.events, event)
	return nil
}

func (m *memoryQuotaJournal) List() ([]models.AuditEvent, error) {
	out := make([]models.AuditEvent, len(m.events))
	copy(out, m.events)
	return out, nil
}

func TestConfigureQuotaObservabilityWritesLifecycleEvents(t *testing.T) {
	quota.ResetTransitionHook()
	quota.ResetDefaultRegistry()
	t.Cleanup(func() {
		quota.ResetTransitionHook()
		quota.ResetDefaultRegistry()
	})

	journal := &memoryQuotaJournal{}
	configureQuotaObservability(journal)

	registry := quota.DefaultRegistry()
	registry.Record(quota.Observation{
		Provider:         "cloudflare",
		Plan:             "cloudflare quota headers",
		QuotaSource:      "headers",
		LimitKnown:       true,
		Limit:            100,
		RemainingKnown:   true,
		Remaining:        20,
		PercentKnown:     true,
		RemainingPercent: 20,
	})
	registry.Record(quota.Observation{
		Provider:         "cloudflare",
		Plan:             "cloudflare quota headers",
		QuotaSource:      "headers",
		LimitKnown:       true,
		Limit:            100,
		RemainingKnown:   true,
		Remaining:        10,
		PercentKnown:     true,
		RemainingPercent: 10,
	})
	registry.Record(quota.Observation{
		Provider:         "cloudflare",
		Plan:             "cloudflare quota headers",
		QuotaSource:      "headers",
		LimitKnown:       true,
		Limit:            100,
		RemainingKnown:   true,
		Remaining:        4,
		PercentKnown:     true,
		RemainingPercent: 4,
	})
	registry.Record(quota.Observation{
		Provider:         "cloudflare",
		Plan:             "cloudflare quota headers",
		QuotaSource:      "headers",
		LimitKnown:       true,
		Limit:            100,
		RemainingKnown:   true,
		Remaining:        42,
		PercentKnown:     true,
		RemainingPercent: 42,
	})

	events, err := journal.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected three quota audit events, got %d", len(events))
	}
	if got := string(events[0].Action); got != "provider_quota_warning" {
		t.Fatalf("unexpected first action: %s", got)
	}
	if got := string(events[1].Action); got != "provider_quota_throttled" {
		t.Fatalf("unexpected second action: %s", got)
	}
	if got := string(events[2].Action); got != "provider_quota_recovered" {
		t.Fatalf("unexpected third action: %s", got)
	}
	if events[0].Target != "cloudflare" || events[1].Target != "cloudflare" || events[2].Target != "cloudflare" {
		t.Fatalf("unexpected targets: %+v", events)
	}
}
