package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

// StateStore persists core runtime metadata.
type StateStore struct {
	dir string
	mu  sync.RWMutex
}

func NewStateStore(dir string) *StateStore {
	return &StateStore{dir: dir}
}

func (s *StateStore) Save(state models.RuntimeState) error {
	const op = "runtime.state.Save"

	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return apperr.Wrap(op, err)
	}

	path := filepath.Join(s.dir, "runtime_state.json")
	tmp := path + ".tmp"

	if err := os.MkdirAll(s.dir, 0755); err != nil {
		return apperr.Wrap(op, err)
	}

	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return apperr.Wrap(op, err)
	}

	return apperr.Wrap(op, os.Rename(tmp, path))
}

func (s *StateStore) SaveForScope(scopeID string, state models.RuntimeState) error {
	const op = "runtime.state.SaveForScope"
	if scopeID == "" {
		return s.Save(state)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return apperr.Wrap(op, err)
	}

	path := filepath.Join(s.dir, scopedStateFile(scopeID))
	tmp := path + ".tmp"

	if err := os.MkdirAll(s.dir, 0755); err != nil {
		return apperr.Wrap(op, err)
	}

	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return apperr.Wrap(op, err)
	}

	return apperr.Wrap(op, os.Rename(tmp, path))
}

func (s *StateStore) Load() (models.RuntimeState, error) {
	const op = "runtime.state.Load"

	s.mu.RLock()
	defer s.mu.RUnlock()

	path := filepath.Join(s.dir, "runtime_state.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
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

func (s *StateStore) LoadForScope(scopeID string) (models.RuntimeState, error) {
	const op = "runtime.state.LoadForScope"
	if scopeID == "" {
		return s.Load()
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	path := filepath.Join(s.dir, scopedStateFile(scopeID))
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s.loadGlobalUnlocked()
		}
		return models.RuntimeState{}, apperr.Wrap(op, err)
	}

	var st models.RuntimeState
	if err := json.Unmarshal(data, &st); err != nil {
		return models.RuntimeState{}, apperr.Wrap(op, err)
	}
	return st, nil
}

func (s *StateStore) loadGlobalUnlocked() (models.RuntimeState, error) {
	const op = "runtime.state.loadGlobalUnlocked"

	path := filepath.Join(s.dir, "runtime_state.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return models.RuntimeState{}, nil
		}
		return models.RuntimeState{}, apperr.Wrap(op, err)
	}

	var st models.RuntimeState
	if err := json.Unmarshal(data, &st); err != nil {
		return models.RuntimeState{}, apperr.Wrap(op, err)
	}

	return st, nil
}

func scopedStateFile(scopeID string) string {
	return fmt.Sprintf("runtime_state_%s.json", scopeID)
}
