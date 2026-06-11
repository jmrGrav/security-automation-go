package ui

import (
	"context"
	"testing"
)

// fakeGateStore is a minimal SetupStorer for gate tests.
type fakeGateStore struct {
	settings map[string]string
}

type fakeCredentialStore struct {
	values map[string]string
}

func (f *fakeGateStore) GetCurrentStep(_ context.Context) (int, error) { return 9, nil }
func (f *fakeGateStore) SetCurrentStep(_ context.Context, _ int) error { return nil }
func (f *fakeGateStore) IsComplete(_ context.Context) (bool, error)    { return false, nil }
func (f *fakeGateStore) MarkComplete(_ context.Context) error          { return nil }
func (f *fakeGateStore) GetSetting(_ context.Context, k string) (string, bool, error) {
	v, ok := f.settings[k]
	return v, ok, nil
}
func (f *fakeGateStore) SetSetting(_ context.Context, k, v string) error {
	if f.settings == nil {
		f.settings = map[string]string{}
	}
	f.settings[k] = v
	return nil
}
func (f *fakeGateStore) GetAuthEpoch(_ context.Context) (int64, error)             { return 0, nil }
func (f *fakeGateStore) IncrementAuthEpoch(_ context.Context) (int64, error)       { return 1, nil }
func (f *fakeGateStore) GetPasswordChangeRequired(_ context.Context) (bool, error) { return false, nil }
func (f *fakeGateStore) SetPasswordChangeRequired(_ context.Context, _ bool) error { return nil }

func (f *fakeCredentialStore) Lookup(_ context.Context, key string) (string, bool, error) {
	v, ok := f.values[key]
	return v, ok, nil
}
func (f *fakeCredentialStore) Set(_ context.Context, key, value string, _ bool) error {
	if f.values == nil {
		f.values = map[string]string{}
	}
	f.values[key] = value
	return nil
}
func (f *fakeCredentialStore) Delete(_ context.Context, key string) error {
	delete(f.values, key)
	return nil
}
func (f *fakeCredentialStore) ImportLegacyDir(_ context.Context, _ string) (int, error) {
	return 0, nil
}

func TestProductionEnableGate_BlockedWhenCFTokenMissing(t *testing.T) {
	store := &fakeGateStore{settings: map[string]string{"cf_zone_id": "zone123"}}
	err := checkProductionEnableReady(store, &fakeCredentialStore{}, context.Background())
	if err == nil {
		t.Error("expected error when CF token is missing")
	}
}

func TestProductionEnableGate_BlockedWhenZoneIDMissing(t *testing.T) {
	store := &fakeGateStore{settings: map[string]string{}}
	creds := &fakeCredentialStore{values: map[string]string{"cloudflare.api_token": "CF_API_TOKEN=v1.0-test"}}
	err := checkProductionEnableReady(store, creds, context.Background())
	if err == nil {
		t.Error("expected error when zone ID is absent")
	}
}

func TestProductionEnableGate_PassesWhenBothConfigured(t *testing.T) {
	store := &fakeGateStore{settings: map[string]string{"cf_zone_id": "zone123abc"}}
	creds := &fakeCredentialStore{values: map[string]string{"cloudflare.api_token": "CF_API_TOKEN=v1.0-test"}}
	err := checkProductionEnableReady(store, creds, context.Background())
	if err != nil {
		t.Errorf("unexpected gate error: %v", err)
	}
}

func TestProductionEnableGate_NilStoreAllowed(t *testing.T) {
	creds := &fakeCredentialStore{values: map[string]string{"cloudflare.api_token": "CF_API_TOKEN=v1.0-test"}}
	err := checkProductionEnableReady(nil, creds, context.Background())
	_ = err
}
