package sqlite

import (
	"context"
	"testing"
)

func newTestNoteStore(t *testing.T) *NoteStore {
	t.Helper()
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := NewNoteStore(db)
	if err != nil {
		t.Fatalf("NewNoteStore: %v", err)
	}
	return store
}

func TestNoteStore_UpsertGetDelete(t *testing.T) {
	s := newTestNoteStore(t)
	ctx := context.Background()

	// Create
	if err := s.Upsert(ctx, "ip", "1.2.3.4", "initial note"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Read
	n, ok, err := s.Get(ctx, "ip", "1.2.3.4")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected note to exist")
	}
	if n.Content != "initial note" {
		t.Errorf("want content %q, got %q", "initial note", n.Content)
	}
	if n.EntityType != "ip" || n.EntityValue != "1.2.3.4" {
		t.Errorf("unexpected entity: type=%q value=%q", n.EntityType, n.EntityValue)
	}
	if n.CreatedAt.IsZero() || n.UpdatedAt.IsZero() {
		t.Error("timestamps must not be zero")
	}

	// Upsert replaces content
	if err := s.Upsert(ctx, "ip", "1.2.3.4", "updated note"); err != nil {
		t.Fatalf("Upsert update: %v", err)
	}
	n2, ok, err := s.Get(ctx, "ip", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("Get after update: err=%v ok=%v", err, ok)
	}
	if n2.Content != "updated note" {
		t.Errorf("want updated content, got %q", n2.Content)
	}

	// Delete
	if err := s.Delete(ctx, "ip", "1.2.3.4"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, ok, err = s.Get(ctx, "ip", "1.2.3.4")
	if err != nil {
		t.Fatalf("Get after delete: %v", err)
	}
	if ok {
		t.Error("expected note to be deleted")
	}
}

func TestNoteStore_List(t *testing.T) {
	s := newTestNoteStore(t)
	ctx := context.Background()

	if err := s.Upsert(ctx, "ip", "10.0.0.1", "note A"); err != nil {
		t.Fatalf("Upsert A: %v", err)
	}
	if err := s.Upsert(ctx, "asn", "AS12345", "note B"); err != nil {
		t.Fatalf("Upsert B: %v", err)
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 notes, got %d", len(list))
	}

	// Verify both entities are present
	found := map[string]bool{}
	for _, n := range list {
		found[n.EntityValue] = true
	}
	if !found["10.0.0.1"] || !found["AS12345"] {
		t.Errorf("expected both entries in list, got %v", list)
	}
}

func TestNoteStore_GetMissing(t *testing.T) {
	s := newTestNoteStore(t)
	ctx := context.Background()

	_, ok, err := s.Get(ctx, "ip", "9.9.9.9")
	if err != nil {
		t.Fatalf("Get missing: expected nil error, got %v", err)
	}
	if ok {
		t.Error("Get missing: expected ok=false")
	}
}
