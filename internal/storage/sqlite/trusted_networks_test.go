package sqlite

import (
	"context"
	"testing"

	"github.com/jm/security-automation-go/internal/trustednetworks"
)

func TestTrustedNetworksStore_UpsertGetList(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewTrustedNetworksStore(db)
	ctx := context.Background()

	if err := store.Upsert(ctx, entry("203.0.113.5", "office", "manual_ui", "trusted office VPN")); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, ok, err := store.Get(ctx, "203.0.113.5")
	if err != nil || !ok {
		t.Fatalf("Get: err=%v ok=%v", err, ok)
	}
	if got.Label != "office" || got.Source != "manual_ui" || got.Comment != "trusted office VPN" {
		t.Fatalf("unexpected entry: %+v", got)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatalf("expected timestamps to be set: %+v", got)
	}

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].Value != "203.0.113.5" {
		t.Fatalf("unexpected list: %+v", list)
	}
}

func TestTrustedNetworksStore_UpsertReplacesExistingByValue(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewTrustedNetworksStore(db)
	ctx := context.Background()

	if err := store.Upsert(ctx, entry("203.0.113.5", "office", "manual_ui", "")); err != nil {
		t.Fatalf("Upsert first: %v", err)
	}
	if err := store.Upsert(ctx, entry("203.0.113.5", "office-renamed", "manual_ui", "updated")); err != nil {
		t.Fatalf("Upsert second: %v", err)
	}

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected exactly 1 row after re-upsert by value, got %d", len(list))
	}
	if list[0].Label != "office-renamed" || list[0].Comment != "updated" {
		t.Fatalf("expected upsert to update in place, got %+v", list[0])
	}
}

func TestTrustedNetworksStore_Remove(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewTrustedNetworksStore(db)
	ctx := context.Background()

	if err := store.Upsert(ctx, entry("203.0.113.5", "office", "manual_ui", "")); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := store.Remove(ctx, "203.0.113.5"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	_, ok, err := store.Get(ctx, "203.0.113.5")
	if err != nil {
		t.Fatalf("Get after Remove: %v", err)
	}
	if ok {
		t.Fatal("expected entry to be gone after Remove")
	}
}

func TestTrustedNetworksStore_GetUnknownReturnsFalse(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewTrustedNetworksStore(db)
	_, ok, err := store.Get(context.Background(), "0.0.0.0")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for unknown value")
	}
}

func entry(value, label, source, comment string) trustednetworks.Entry {
	return trustednetworks.Entry{Value: value, Label: label, Source: source, Comment: comment}
}
