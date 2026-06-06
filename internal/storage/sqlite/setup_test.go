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
