package fs

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

// RuntimeStateStore implements storage.RuntimeStateStore using JSON files.
type RuntimeStateStore struct {
	mu   sync.RWMutex
	path string
}

func NewRuntimeStateStore(dir string) *RuntimeStateStore {
	return &RuntimeStateStore{
		path: filepath.Join(dir, "runtime_state.json"),
	}
}

func (s *RuntimeStateStore) Load(ctx context.Context) (models.RuntimeState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	const op = "storage.fs.Load"
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return models.RuntimeState{}, nil
		}
		return models.RuntimeState{}, apperr.Wrap(op, err)
	}

	var state models.RuntimeState
	if err := json.Unmarshal(data, &state); err != nil {
		return models.RuntimeState{}, apperr.Wrap(op, err)
	}

	return state, nil
}

func (s *RuntimeStateStore) Save(ctx context.Context, state models.RuntimeState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	const op = "storage.fs.Save"
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return apperr.Wrap(op, err)
	}

	dir := filepath.Dir(s.path)
	_ = os.MkdirAll(dir, 0755)

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return apperr.Wrap(op, err)
	}

	return apperr.Wrap(op, os.Rename(tmp, s.path))
}
