package ui

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// fakeGateStore is a minimal SetupStorer for gate tests.
type fakeGateStore struct {
	settings map[string]string
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

// TestProductionEnableGate_BlockedWhenCFTokenMissing verifies that enabling
// production mode is rejected when the Cloudflare token file does not exist.
func TestProductionEnableGate_BlockedWhenCFTokenMissing(t *testing.T) {
	// Temporarily redirect cfTokenSecretPath to a non-existent file.
	orig := cfTokenSecretPath
	cfTokenSecretPath = filepath.Join(t.TempDir(), "nonexistent_token")
	defer func() { cfTokenSecretPath = orig }()

	store := &fakeGateStore{settings: map[string]string{"cf_zone_id": "zone123"}}
	err := checkProductionEnableReady(store, context.Background())
	if err == nil {
		t.Error("expected error when CF token file is missing")
	}
}

// TestProductionEnableGate_BlockedWhenZoneIDMissing verifies that production
// mode is rejected when the Zone ID was never configured.
func TestProductionEnableGate_BlockedWhenZoneIDMissing(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "cloudflare_api_token")
	if err := os.WriteFile(tokenPath, []byte("CF_API_TOKEN=v1.0-test"), 0o600); err != nil {
		t.Fatal(err)
	}

	orig := cfTokenSecretPath
	cfTokenSecretPath = tokenPath
	defer func() { cfTokenSecretPath = orig }()

	store := &fakeGateStore{settings: map[string]string{}} // no zone_id
	err := checkProductionEnableReady(store, context.Background())
	if err == nil {
		t.Error("expected error when zone ID is absent")
	}
}

// TestProductionEnableGate_PassesWhenBothConfigured verifies that the gate
// passes when both the CF token file and zone ID are present (and no legacy-only layout).
func TestProductionEnableGate_PassesWhenBothConfigured(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "cloudflare_api_token")
	if err := os.WriteFile(tokenPath, []byte("CF_API_TOKEN=v1.0-test"), 0o600); err != nil {
		t.Fatal(err)
	}

	orig := cfTokenSecretPath
	cfTokenSecretPath = tokenPath
	defer func() { cfTokenSecretPath = orig }()

	store := &fakeGateStore{settings: map[string]string{"cf_zone_id": "zone123abc"}}
	// The legacy layout check uses fixed paths on disk. In a dev/CI environment
	// neither /etc/security-automation nor /etc/security-automation-go/secrets
	// typically exists, so CheckLayout returns LayoutOK — gate passes.
	err := checkProductionEnableReady(store, context.Background())
	if err != nil {
		// Only fail if the error is not about legacy layout (could exist on some CI hosts).
		t.Errorf("unexpected gate error: %v", err)
	}
}

// TestProductionEnableGate_NilStoreAllowed verifies that a nil store does not
// panic — production enable with nil store only checks the CF token file.
func TestProductionEnableGate_NilStoreAllowed(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "cloudflare_api_token")
	if err := os.WriteFile(tokenPath, []byte("CF_API_TOKEN=v1.0-test"), 0o600); err != nil {
		t.Fatal(err)
	}

	orig := cfTokenSecretPath
	cfTokenSecretPath = tokenPath
	defer func() { cfTokenSecretPath = orig }()

	// nil store skips zone ID check — should not panic
	err := checkProductionEnableReady(nil, context.Background())
	// no zone check with nil store, so should pass (or fail on layout, not panic)
	_ = err
}
