package providerstate

import (
	"context"
	"testing"
	"time"
)

type memoryStore struct {
	values map[string]string
}

func (m *memoryStore) GetSetting(_ context.Context, key string) (string, bool, error) {
	if m.values == nil {
		return "", false, nil
	}
	v, ok := m.values[key]
	return v, ok, nil
}

func (m *memoryStore) SetSetting(_ context.Context, key, value string) error {
	if m.values == nil {
		m.values = make(map[string]string)
	}
	m.values[key] = value
	return nil
}

func TestRuntimeStateRoundTripIncludesHealthFields(t *testing.T) {
	ctx := context.Background()
	store := &memoryStore{}
	want := RuntimeState{
		Enabled:       true,
		Healthy:       true,
		LastTestAt:    time.Date(2026, 6, 13, 10, 11, 12, 0, time.UTC),
		LastSuccessAt: time.Date(2026, 6, 13, 10, 15, 12, 0, time.UTC),
		LastFailureAt: time.Date(2026, 6, 13, 10, 16, 12, 0, time.UTC),
		LastLatencyMS: 182,
		LastErrorCode: "AUTH_FAILED",
	}

	if err := Save(ctx, store, "openai", want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, ok, err := Load(ctx, store, "openai")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !ok {
		t.Fatal("expected runtime state to be present")
	}
	if got.Enabled != want.Enabled || got.Healthy != want.Healthy || !got.LastTestAt.Equal(want.LastTestAt) || !got.LastSuccessAt.Equal(want.LastSuccessAt) || !got.LastFailureAt.Equal(want.LastFailureAt) || got.LastLatencyMS != want.LastLatencyMS || got.LastErrorCode != want.LastErrorCode {
		t.Fatalf("round-trip mismatch: got %#v want %#v", got, want)
	}
}

func TestRuntimeStateAbsentReturnsFalse(t *testing.T) {
	got, ok, err := Load(context.Background(), &memoryStore{}, "spamhaus")
	if err != nil {
		t.Fatalf("load absent: %v", err)
	}
	if ok {
		t.Fatalf("expected absent runtime state")
	}
	if got.Enabled || got.Healthy || got.LastLatencyMS != 0 || got.LastErrorCode != "" {
		t.Fatalf("expected zero value absent state, got %#v", got)
	}
}

func TestDisabledErrorHasStableMessage(t *testing.T) {
	if got := ErrDisabled.Error(); got != "provider disabled by operator" {
		t.Fatalf("unexpected disabled error message: %q", got)
	}
}
