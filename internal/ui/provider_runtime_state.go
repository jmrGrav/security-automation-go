package ui

import (
	"context"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/providerstate"
)

type providerRuntimeSnapshot struct {
	Configured     bool
	Enabled        bool
	Healthy        bool
	LastTestAt     time.Time
	LastSuccessAt  time.Time
	LastFailureAt  time.Time
	LastLatencyMS  int
	LastTestStatus string
	LastErrorCode  string
}

func clearProviderRuntimeDiagnostics(snapshot *providerRuntimeSnapshot) {
	if snapshot == nil {
		return
	}
	snapshot.Healthy = false
	snapshot.LastTestAt = time.Time{}
	snapshot.LastSuccessAt = time.Time{}
	snapshot.LastFailureAt = time.Time{}
	snapshot.LastLatencyMS = 0
	snapshot.LastTestStatus = ""
	snapshot.LastErrorCode = ""
}

func providerDisplaySnapshot(snapshot providerRuntimeSnapshot) providerRuntimeSnapshot {
	display := snapshot
	switch {
	case !display.Enabled:
		clearProviderRuntimeDiagnostics(&display)
		display.Enabled = false
		display.LastTestStatus = providerTestDisabledByOperator
	case display.Healthy:
		display.LastTestStatus = providerTestReady
		display.LastErrorCode = ""
		display.LastFailureAt = time.Time{}
		if display.LastSuccessAt.IsZero() {
			display.LastSuccessAt = display.LastTestAt
		}
	}
	return display
}

func providerRuntimeKey(slug string) string {
	return strings.ToLower(strings.TrimSpace(slug))
}

func loadProviderRuntimeSnapshot(ctx context.Context, store providerstate.Store, slug string) (providerRuntimeSnapshot, bool, error) {
	if store == nil {
		return providerRuntimeSnapshot{}, false, nil
	}
	state, ok, err := providerstate.Load(ctx, store, providerRuntimeKey(slug))
	if err != nil {
		return providerRuntimeSnapshot{}, false, err
	}
	return providerRuntimeSnapshot{
		Enabled:        state.Enabled,
		Healthy:        state.Healthy,
		LastTestAt:     state.LastTestAt,
		LastSuccessAt:  state.LastSuccessAt,
		LastFailureAt:  state.LastFailureAt,
		LastLatencyMS:  state.LastLatencyMS,
		LastTestStatus: state.LastTestStatus,
		LastErrorCode:  state.LastErrorCode,
	}, ok, nil
}

func saveProviderRuntimeSnapshot(ctx context.Context, store providerstate.Store, slug string, snapshot providerRuntimeSnapshot) error {
	if store == nil {
		return nil
	}
	return providerstate.Save(ctx, store, providerRuntimeKey(slug), providerstate.RuntimeState{
		Enabled:        snapshot.Enabled,
		Healthy:        snapshot.Healthy,
		LastTestAt:     snapshot.LastTestAt,
		LastSuccessAt:  snapshot.LastSuccessAt,
		LastFailureAt:  snapshot.LastFailureAt,
		LastLatencyMS:  snapshot.LastLatencyMS,
		LastTestStatus: snapshot.LastTestStatus,
		LastErrorCode:  snapshot.LastErrorCode,
	})
}

func providerHealthStateText(configured, enabled, healthy bool) string {
	switch {
	case !configured && !enabled:
		return "not configured"
	case !configured:
		return "missing secret"
	case !enabled:
		return "disabled by operator"
	case healthy:
		return "healthy"
	default:
		return "warning"
	}
}

func providerLastTestStatusText(enabled, healthy bool, raw string) string {
	normalized := strings.TrimSpace(raw)
	if !enabled {
		return "provider disabled by operator"
	}
	if healthy {
		return "ready"
	}
	if normalized == "" {
		return "no test yet"
	}
	if enabled && providerDiagnosticCode(normalized) == providerTestDisabledByOperator {
		return "no test yet"
	}
	return providerDiagnosticLabel(normalized)
}

func providerLastErrorText(enabled, healthy bool, raw string) string {
	normalized := strings.TrimSpace(raw)
	if !enabled || healthy {
		return "no error"
	}
	if normalized == "" || strings.EqualFold(normalized, "none") {
		return "no error"
	}
	if providerDiagnosticCode(normalized) == providerTestDisabledByOperator {
		return "no error"
	}
	return displayProviderErrorCode(normalized)
}

func providerLastSuccessText(enabled, healthy bool, lastTestAt, lastSuccessAt time.Time) string {
	if !enabled {
		return "never"
	}
	if !lastSuccessAt.IsZero() {
		return formatProviderTime(lastSuccessAt)
	}
	if healthy && !lastTestAt.IsZero() {
		return formatProviderTime(lastTestAt)
	}
	return "never"
}

func providerLastFailureText(enabled, healthy bool, lastTestAt, lastFailureAt time.Time) string {
	if !enabled || healthy {
		return "never"
	}
	if !lastFailureAt.IsZero() {
		return formatProviderTime(lastFailureAt)
	}
	if !healthy && !lastTestAt.IsZero() {
		return formatProviderTime(lastTestAt)
	}
	return "never"
}

func providerSummaryStateText(configured, enabled, healthy bool) string {
	switch {
	case !enabled && !configured:
		return "disabled"
	case !enabled:
		return "disabled"
	case !configured:
		return "missing secret"
	case healthy:
		return "ready"
	default:
		return "warning"
	}
}

func providerEnabledLabel(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func providerHealthModeText(healthy, enabled bool) string {
	switch {
	case !enabled:
		return "disabled"
	case healthy:
		return "healthy"
	default:
		return "warning"
	}
}

func providerHealthValidationText(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

func providerRuntimeEnabled(ctx context.Context, store providerstate.Store, slug string, fallback bool) bool {
	if store == nil {
		return fallback
	}
	state, ok, err := providerstate.Load(ctx, store, providerRuntimeKey(slug))
	if err != nil || !ok {
		return fallback
	}
	return state.Enabled
}

func (s *Server) credentialValue(ctx context.Context, key string) (string, bool) {
	if s == nil || s.credentialStore == nil {
		return "", false
	}
	v, ok, err := s.credentialStore.Lookup(ctx, key)
	if err != nil || !ok {
		return "", false
	}
	return strings.TrimSpace(v), true
}
