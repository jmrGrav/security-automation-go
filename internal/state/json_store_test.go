package state

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
)

func TestJSONStoreSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	store := NewJSONStore(dir)

	type payload struct {
		Name string `json:"name"`
	}

	src := payload{Name: "example"}
	if err := store.Save(context.Background(), "state.json", src); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	var dst payload
	if err := store.Load(context.Background(), "state.json", &dst); err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if dst.Name != src.Name {
		t.Fatalf("unexpected payload: %#v", dst)
	}

	if _, err := filepath.Abs(dir); err != nil {
		t.Fatalf("unexpected temp dir issue: %v", err)
	}
}

func TestJSONStoreLoadMissingFileIsNotAnError(t *testing.T) {
	store := NewJSONStore(t.TempDir())

	var dst map[string]string
	if err := store.Load(context.Background(), "missing.json", &dst); err != nil {
		t.Fatalf("expected nil error for missing file, got %v", err)
	}
}

func TestJSONStoreConcurrentSaveAndLoad(t *testing.T) {
	store := NewJSONStore(t.TempDir())
	ctx := context.Background()

	type payload struct {
		Value int `json:"value"`
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			if err := store.Save(ctx, "state.json", payload{Value: v}); err != nil {
				t.Errorf("Save returned error: %v", err)
				return
			}

			var out payload
			if err := store.Load(ctx, "state.json", &out); err != nil {
				t.Errorf("Load returned error: %v", err)
			}
		}(i)
	}
	wg.Wait()
}
