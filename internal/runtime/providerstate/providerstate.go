package providerstate

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Store is the minimal setting store needed by provider runtime state helpers.
type Store interface {
	GetSetting(ctx context.Context, key string) (string, bool, error)
	SetSetting(ctx context.Context, key, value string) error
}

// RuntimeState captures operator-visible runtime diagnostics for a provider.
type RuntimeState struct {
	Enabled        bool
	Healthy        bool
	LastTestAt     time.Time
	LastSuccessAt  time.Time
	LastFailureAt  time.Time
	LastLatencyMS  int
	LastTestStatus string
	LastErrorCode  string
}

var ErrDisabled = errors.New("provider disabled by operator")

func EnabledKey(name string) string        { return key(name, "enabled") }
func HealthyKey(name string) string        { return key(name, "healthy") }
func LastTestAtKey(name string) string     { return key(name, "last_test_at") }
func LastSuccessAtKey(name string) string  { return key(name, "last_success_at") }
func LastFailureAtKey(name string) string  { return key(name, "last_failure_at") }
func LastLatencyKey(name string) string    { return key(name, "last_latency_ms") }
func LastTestStatusKey(name string) string { return key(name, "last_test_status") }
func LastErrorKey(name string) string      { return key(name, "last_error_code") }

func key(name, field string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	field = strings.ToLower(strings.TrimSpace(field))
	return "provider." + name + "." + field
}

// Load returns the persisted state for a provider.
func Load(ctx context.Context, store Store, name string) (RuntimeState, bool, error) {
	if store == nil {
		return RuntimeState{}, false, nil
	}
	var state RuntimeState
	seen := false
	for _, item := range []struct {
		key  string
		load func(string) error
	}{
		{EnabledKey(name), func(v string) error { b, _ := strconv.ParseBool(v); state.Enabled = b; return nil }},
		{HealthyKey(name), func(v string) error { b, _ := strconv.ParseBool(v); state.Healthy = b; return nil }},
		{LastTestAtKey(name), func(v string) error {
			if v == "" {
				return nil
			}
			ts, err := time.Parse(time.RFC3339, v)
			if err == nil {
				state.LastTestAt = ts
			}
			return err
		}},
		{LastSuccessAtKey(name), func(v string) error {
			if v == "" {
				return nil
			}
			ts, err := time.Parse(time.RFC3339, v)
			if err == nil {
				state.LastSuccessAt = ts
			}
			return err
		}},
		{LastFailureAtKey(name), func(v string) error {
			if v == "" {
				return nil
			}
			ts, err := time.Parse(time.RFC3339, v)
			if err == nil {
				state.LastFailureAt = ts
			}
			return err
		}},
		{LastLatencyKey(name), func(v string) error {
			if v == "" {
				return nil
			}
			n, err := strconv.Atoi(v)
			if err == nil {
				state.LastLatencyMS = n
			}
			return err
		}},
		{LastTestStatusKey(name), func(v string) error { state.LastTestStatus = v; return nil }},
		{LastErrorKey(name), func(v string) error { state.LastErrorCode = v; return nil }},
	} {
		v, ok, err := store.GetSetting(ctx, item.key)
		if err != nil {
			return RuntimeState{}, false, err
		}
		if !ok {
			continue
		}
		seen = true
		if err := item.load(v); err != nil {
			return RuntimeState{}, false, fmt.Errorf("parse %s: %w", item.key, err)
		}
	}
	return state, seen, nil
}

// Save persists the provider runtime state.
func Save(ctx context.Context, store Store, name string, state RuntimeState) error {
	if store == nil {
		return nil
	}
	values := map[string]string{
		EnabledKey(name):        strconv.FormatBool(state.Enabled),
		HealthyKey(name):        strconv.FormatBool(state.Healthy),
		LastTestAtKey(name):     formatTime(state.LastTestAt),
		LastSuccessAtKey(name):  formatTime(state.LastSuccessAt),
		LastFailureAtKey(name):  formatTime(state.LastFailureAt),
		LastLatencyKey(name):    strconv.Itoa(state.LastLatencyMS),
		LastTestStatusKey(name): state.LastTestStatus,
		LastErrorKey(name):      state.LastErrorCode,
	}
	for key, value := range values {
		if err := store.SetSetting(ctx, key, value); err != nil {
			return err
		}
	}
	return nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
