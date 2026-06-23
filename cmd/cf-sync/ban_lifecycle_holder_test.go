package main

import (
	"context"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
)

// fakeBanLifecycleStore is a minimal in-memory banlifecycle.Store for
// testing lazyBanLifecycleStore without SQLite.
type fakeBanLifecycleStore struct {
	entries map[string]banlifecycle.Entry
}

func newFakeBanLifecycleStore() *fakeBanLifecycleStore {
	return &fakeBanLifecycleStore{entries: make(map[string]banlifecycle.Entry)}
}

func (f *fakeBanLifecycleStore) Upsert(ctx context.Context, e banlifecycle.Entry) error {
	f.entries[e.IP] = e
	return nil
}

func (f *fakeBanLifecycleStore) Get(ctx context.Context, ip string) (banlifecycle.Entry, bool, error) {
	e, ok := f.entries[ip]
	return e, ok, nil
}

func (f *fakeBanLifecycleStore) Active(ctx context.Context) ([]banlifecycle.Entry, error) {
	var out []banlifecycle.Entry
	for _, e := range f.entries {
		if e.Status == "active" {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeBanLifecycleStore) Expired(ctx context.Context, now time.Time) ([]banlifecycle.Entry, error) {
	return nil, nil
}

func (f *fakeBanLifecycleStore) MarkStatus(ctx context.Context, ip string, status string, note string) error {
	e := f.entries[ip]
	e.Status = status
	f.entries[ip] = e
	return nil
}

func (f *fakeBanLifecycleStore) RecordCleanupFailure(ctx context.Context, ip string, errMsg string) error {
	return nil
}

func (f *fakeBanLifecycleStore) Recent(ctx context.Context, limit int) ([]banlifecycle.Entry, error) {
	var out []banlifecycle.Entry
	for _, e := range f.entries {
		out = append(out, e)
	}
	return out, nil
}

func (f *fakeBanLifecycleStore) RecidiveLevel(ctx context.Context, ip string) (int, error) {
	return 0, nil
}

// TestLazyBanLifecycleStore_ReflectsLateBoundInnerStore reproduces the
// daemon+UI startup race this holder exists to fix: the UI goroutine
// constructs its dependency on the holder before the daemon has opened the
// scoped runtime DB and called set(). Reads issued in that window must not
// be permanently bound to a stale/empty store — once set() is called with
// the real store, subsequent reads (the same ones a page handler would
// issue) must see data written through that real store.
func TestLazyBanLifecycleStore_ReflectsLateBoundInnerStore(t *testing.T) {
	holder := &lazyBanLifecycleStore{}
	ctx := context.Background()

	// Simulate the UI page handler reading before the daemon has wired the
	// real store: must return an empty, error-free result, not panic or
	// permanently cache "no data".
	active, err := holder.Active(ctx)
	if err != nil || len(active) != 0 {
		t.Fatalf("before set(): Active() = (%v, %v), want (nil/empty, nil)", active, err)
	}

	// Daemon finishes scope resolution and opens the real scoped DB-backed
	// store, then wires it into the holder — exactly like
	// banLifecycleHolder.set(banLifecycleStore) in runtime.go.
	real := newFakeBanLifecycleStore()
	if err := real.Upsert(ctx, banlifecycle.Entry{IP: "203.0.113.5", Status: "active"}); err != nil {
		t.Fatalf("seed real store: %v", err)
	}
	holder.set(real)

	// The UI's next read of the SAME holder instance (no new construction,
	// exactly as ui.NewServer holds a single long-lived reference) must now
	// see the real entry — this is the split-brain bug this holder fixes:
	// without it, the UI's store was permanently bound to the unscoped,
	// always-empty bootstrap DB at construction time.
	active, err = holder.Active(ctx)
	if err != nil {
		t.Fatalf("after set(): Active() error = %v", err)
	}
	if len(active) != 1 || active[0].IP != "203.0.113.5" {
		t.Fatalf("after set(): Active() = %+v, want one entry for 203.0.113.5", active)
	}

	entry, ok, err := holder.Get(ctx, "203.0.113.5")
	if err != nil || !ok || entry.IP != "203.0.113.5" {
		t.Fatalf("after set(): Get() = (%+v, %v, %v), want the seeded entry", entry, ok, err)
	}
}

// TestLazyBanLifecycleStore_SatisfiesStoreInterface is a compile-time-ish
// guard kept as a runtime test too: ui.Options.BanLifecycleStore requires
// banlifecycle.Store: a regression here would break the UI wiring this
// holder is for.
func TestLazyBanLifecycleStore_SatisfiesStoreInterface(t *testing.T) {
	var _ banlifecycle.Store = &lazyBanLifecycleStore{}
}
