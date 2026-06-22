package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	csmodels "github.com/jm/security-automation-go/internal/crowdsec/models"
	"github.com/jm/security-automation-go/internal/trustednetworks"
)

type allowlistFakeCrowdSec struct {
	entries []csmodels.AllowlistEntry
	err     error
	calls   int
}

func (f *allowlistFakeCrowdSec) ListAllowlist(_ context.Context, _ string) ([]csmodels.AllowlistEntry, error) {
	f.calls++
	return append([]csmodels.AllowlistEntry(nil), f.entries...), f.err
}

func (f *allowlistFakeCrowdSec) AddAllowlistEntry(context.Context, string, csmodels.AllowlistEntry) error {
	return nil
}

type allowlistFakeTNStore struct {
	entries []trustednetworks.Entry
	err     error
}

func (f *allowlistFakeTNStore) List(context.Context) ([]trustednetworks.Entry, error) {
	return append([]trustednetworks.Entry(nil), f.entries...), f.err
}
func (f *allowlistFakeTNStore) Get(context.Context, string) (trustednetworks.Entry, bool, error) {
	return trustednetworks.Entry{}, false, nil
}
func (f *allowlistFakeTNStore) Upsert(context.Context, trustednetworks.Entry) error { return nil }
func (f *allowlistFakeTNStore) Remove(context.Context, string) error                { return nil }

type allowlistFakeStatusStore struct {
	puts []trustednetworks.CrowdSecAllowlistStatus
}

func (f *allowlistFakeStatusStore) GetCrowdSecAllowlistStatus(context.Context, string) (trustednetworks.CrowdSecAllowlistStatus, bool, error) {
	if len(f.puts) == 0 {
		return trustednetworks.CrowdSecAllowlistStatus{}, false, nil
	}
	return f.puts[len(f.puts)-1], true, nil
}

func (f *allowlistFakeStatusStore) PutCrowdSecAllowlistStatus(_ context.Context, status trustednetworks.CrowdSecAllowlistStatus) error {
	f.puts = append(f.puts, status)
	return nil
}

func newTestAllowlistSyncApp(cs trustednetworks.CrowdSecSpoke, tnStore trustednetworks.Store, statusStore trustednetworks.CrowdSecStatusStore, allowlistName, mode string) *AllowlistSyncApp {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := &trustednetworks.Registry{
		Store:                 tnStore,
		Mode:                  mode,
		Logger:                logger,
		CrowdSec:              cs,
		CrowdSecAllowlistName: allowlistName,
	}
	return &AllowlistSyncApp{logger: logger, reg: reg, statusStore: statusStore}
}

func TestAllowlistSyncListsEntriesWithoutMutation(t *testing.T) {
	cs := &allowlistFakeCrowdSec{entries: []csmodels.AllowlistEntry{{Value: "1.2.3.4"}}}
	tnStore := &allowlistFakeTNStore{entries: []trustednetworks.Entry{{Value: "1.2.3.4"}}}
	statusStore := &allowlistFakeStatusStore{}
	app := newTestAllowlistSyncApp(cs, tnStore, statusStore, "my_allowlist", "shadow")

	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("allowlist sync: %v", err)
	}
	if cs.calls != 1 {
		t.Fatalf("expected exactly one allowlist fetch, got %d", cs.calls)
	}
	if len(statusStore.puts) != 1 {
		t.Fatalf("expected exactly one persisted status, got %d", len(statusStore.puts))
	}
	got := statusStore.puts[0]
	if !got.Configured || !got.AuthOK || got.LastError != "" {
		t.Fatalf("expected configured+auth_ok status with no error, got %#v", got)
	}
	if got.DesiredCount != 1 || got.CurrentCount != 1 {
		t.Fatalf("expected desired=1 current=1, got %#v", got)
	}
}

func TestAllowlistSyncFailsClosedOnAllowlistError(t *testing.T) {
	cs := &allowlistFakeCrowdSec{err: errors.New("cscli failed")}
	tnStore := &allowlistFakeTNStore{}
	statusStore := &allowlistFakeStatusStore{}
	app := newTestAllowlistSyncApp(cs, tnStore, statusStore, "my_allowlist", "shadow")

	if err := app.Run(context.Background()); err == nil {
		t.Fatal("expected allowlist sync to fail closed on allowlist error")
	}
	if len(statusStore.puts) != 1 {
		t.Fatalf("expected the failure to still be persisted, got %d puts", len(statusStore.puts))
	}
	got := statusStore.puts[0]
	if got.AuthOK {
		t.Fatalf("expected auth_ok=false on cscli error, got %#v", got)
	}
	if got.LastError == "" {
		t.Fatal("expected a non-empty last_error on cscli failure")
	}
}

func TestAllowlistSyncDisabledWhenNoAllowlistName(t *testing.T) {
	cs := &allowlistFakeCrowdSec{}
	tnStore := &allowlistFakeTNStore{}
	statusStore := &allowlistFakeStatusStore{}
	app := newTestAllowlistSyncApp(cs, tnStore, statusStore, "", "shadow")

	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("expected no-op when allowlist name is empty, got %v", err)
	}
	if cs.calls != 0 {
		t.Fatalf("expected cscli never invoked when disabled, got %d calls", cs.calls)
	}
	if len(statusStore.puts) != 0 {
		t.Fatalf("expected no status persisted when disabled, got %d", len(statusStore.puts))
	}
}

func TestAllowlistSyncNeverPushesInShadowMode(t *testing.T) {
	cs := &allowlistFakeCrowdSec{entries: nil} // remote allowlist empty
	tnStore := &allowlistFakeTNStore{entries: []trustednetworks.Entry{{Value: "10.0.0.0/24"}}}
	statusStore := &allowlistFakeStatusStore{}
	app := newTestAllowlistSyncApp(cs, tnStore, statusStore, "my_allowlist", "shadow")

	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("allowlist sync: %v", err)
	}
	got := statusStore.puts[0]
	if got.CurrentCount != 0 {
		t.Fatalf("shadow mode must never push: expected current_count=0, got %d", got.CurrentCount)
	}
	if got.DesiredCount != 1 {
		t.Fatalf("expected desired_count=1, got %d", got.DesiredCount)
	}
}
