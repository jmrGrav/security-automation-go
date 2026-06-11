package sqlite

import (
	"context"
	"testing"
)

func newTestSetupStore(t *testing.T) *SetupStore {
	t.Helper()
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewSetupStore(db)
}

func TestSetupStore_DefaultStep(t *testing.T) {
	s := newTestSetupStore(t)
	step, err := s.GetCurrentStep(context.Background())
	if err != nil {
		t.Fatalf("GetCurrentStep: %v", err)
	}
	if step != 1 {
		t.Errorf("want step 1, got %d", step)
	}
}

func TestSetupStore_SetAndGetStep(t *testing.T) {
	s := newTestSetupStore(t)
	if err := s.SetCurrentStep(context.Background(), 4); err != nil {
		t.Fatalf("SetCurrentStep: %v", err)
	}
	step, err := s.GetCurrentStep(context.Background())
	if err != nil {
		t.Fatalf("GetCurrentStep: %v", err)
	}
	if step != 4 {
		t.Errorf("want step 4, got %d", step)
	}
}

func TestSetupStore_IsCompleteDefault(t *testing.T) {
	s := newTestSetupStore(t)
	ok, err := s.IsComplete(context.Background())
	if err != nil {
		t.Fatalf("IsComplete: %v", err)
	}
	if ok {
		t.Error("new store should not be complete")
	}
}

func TestSetupStore_MarkComplete(t *testing.T) {
	s := newTestSetupStore(t)
	if err := s.MarkComplete(context.Background()); err != nil {
		t.Fatalf("MarkComplete: %v", err)
	}
	ok, err := s.IsComplete(context.Background())
	if err != nil {
		t.Fatalf("IsComplete: %v", err)
	}
	if !ok {
		t.Error("should be complete after MarkComplete")
	}
	// Verify step was also advanced to 9
	step, err := s.GetCurrentStep(context.Background())
	if err != nil {
		t.Fatalf("GetCurrentStep after MarkComplete: %v", err)
	}
	if step != 9 {
		t.Errorf("want step 9 after MarkComplete, got %d", step)
	}
}

func TestSetupStore_Settings(t *testing.T) {
	s := newTestSetupStore(t)
	_, ok, err := s.GetSetting(context.Background(), "ui_addr")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if ok {
		t.Error("should be missing before set")
	}

	if err := s.SetSetting(context.Background(), "ui_addr", "127.0.0.1:9091"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	val, ok, err := s.GetSetting(context.Background(), "ui_addr")
	if err != nil {
		t.Fatalf("GetSetting after set: %v", err)
	}
	if !ok {
		t.Fatal("should exist after set")
	}
	if val != "127.0.0.1:9091" {
		t.Errorf("want '127.0.0.1:9091', got %q", val)
	}
}

func TestSetupStore_SetSettingOverwrite(t *testing.T) {
	s := newTestSetupStore(t)
	_ = s.SetSetting(context.Background(), "key", "first")
	_ = s.SetSetting(context.Background(), "key", "second")
	val, _, _ := s.GetSetting(context.Background(), "key")
	if val != "second" {
		t.Errorf("want 'second', got %q", val)
	}
}

func TestSetupStoreRuntimeFlags(t *testing.T) {
	s := newTestSetupStore(t)
	ctx := context.Background()

	// Defaults: unset flags return false
	flags, err := s.GetRuntimeFlags(ctx)
	if err != nil {
		t.Fatalf("GetRuntimeFlags: %v", err)
	}
	if flags.CSPollerEnabled {
		t.Error("want CSPollerEnabled=false by default")
	}
	if flags.CloudflareMutationsEnabled {
		t.Error("want CloudflareMutationsEnabled=false by default")
	}
	if flags.AbuseIPDBEnabled {
		t.Error("want AbuseIPDBEnabled=false by default")
	}
	if flags.BetterStackEnabled {
		t.Error("want BetterStackEnabled=false by default")
	}

	// Set one flag; others remain false
	if err := s.SetRuntimeFlag(ctx, "cs_poller_enabled", true); err != nil {
		t.Fatalf("SetRuntimeFlag: %v", err)
	}
	flags2, err := s.GetRuntimeFlags(ctx)
	if err != nil {
		t.Fatalf("GetRuntimeFlags after set: %v", err)
	}
	if !flags2.CSPollerEnabled {
		t.Error("want CSPollerEnabled=true after set")
	}
	if flags2.CloudflareMutationsEnabled {
		t.Error("want CloudflareMutationsEnabled still false")
	}

	// Round-trip false
	if err := s.SetRuntimeFlag(ctx, "cs_poller_enabled", false); err != nil {
		t.Fatalf("SetRuntimeFlag false: %v", err)
	}
	flags3, _ := s.GetRuntimeFlags(ctx)
	if flags3.CSPollerEnabled {
		t.Error("want CSPollerEnabled=false after unset")
	}

	// Test all four flags round-trip
	for _, key := range []string{"cloudflare_mutations_enabled", "abuseipdb_enabled", "betterstack_enabled"} {
		if err := s.SetRuntimeFlag(ctx, key, true); err != nil {
			t.Fatalf("SetRuntimeFlag %s: %v", key, err)
		}
	}
	flags4, err := s.GetRuntimeFlags(ctx)
	if err != nil {
		t.Fatalf("GetRuntimeFlags all-true: %v", err)
	}
	if !flags4.CloudflareMutationsEnabled {
		t.Error("want CloudflareMutationsEnabled=true")
	}
	if !flags4.AbuseIPDBEnabled {
		t.Error("want AbuseIPDBEnabled=true")
	}
	if !flags4.BetterStackEnabled {
		t.Error("want BetterStackEnabled=true")
	}

	// Unknown key must return error
	if err := s.SetRuntimeFlag(ctx, "unknown_flag", true); err == nil {
		t.Error("want error for unknown flag key")
	}
}
