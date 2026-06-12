package shadow

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Store persists cycle records as append-only JSONL.
// One JSON object per line — efficient for streaming append and tail-reading.
type Store struct {
	path string
}

// NewStore creates a Store backed by a JSONL file at the given path.
func NewStore(stateDir string) *Store {
	return &Store{path: filepath.Join(stateDir, "shadow-cycles.jsonl")}
}

// Append writes one cycle record to the log.
func (s *Store) Append(c Cycle) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return fmt.Errorf("shadow.Store.Append: mkdir: %w", err)
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("shadow.Store.Append: open: %w", err)
	}
	defer f.Close()
	line, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("shadow.Store.Append: marshal: %w", err)
	}
	_, err = fmt.Fprintf(f, "%s\n", line)
	return err
}

// ReadAll returns all cycle records, oldest first.
func (s *Store) ReadAll() ([]Cycle, error) {
	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("shadow.Store.ReadAll: %w", err)
	}
	defer f.Close()

	var cycles []Cycle
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		var c Cycle
		if err := json.Unmarshal(scanner.Bytes(), &c); err != nil {
			continue
		}
		cycles = append(cycles, c)
	}
	return cycles, scanner.Err()
}

// ReadSince returns cycle records on or after the given time.
func (s *Store) ReadSince(since time.Time) ([]Cycle, error) {
	all, err := s.ReadAll()
	if err != nil {
		return nil, err
	}
	var filtered []Cycle
	for _, c := range all {
		if !c.CycleAt.Before(since) {
			filtered = append(filtered, c)
		}
	}
	return filtered, nil
}

// LastN returns the most recent n cycle records (or all if fewer exist).
func (s *Store) LastN(n int) ([]Cycle, error) {
	all, err := s.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(all) <= n {
		return all, nil
	}
	return all[len(all)-n:], nil
}

// Prune removes records older than the retention window.
// Rewrites the file atomically to avoid unbounded growth.
func (s *Store) Prune(retainSince time.Time) error {
	all, err := s.ReadAll()
	if err != nil || len(all) == 0 {
		return err
	}

	var keep []Cycle
	for _, c := range all {
		if !c.CycleAt.Before(retainSince) {
			keep = append(keep, c)
		}
	}
	if len(keep) == len(all) {
		return nil // nothing pruned
	}

	tmp := s.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("shadow.Store.Prune: create tmp: %w", err)
	}
	for _, c := range keep {
		line, _ := json.Marshal(c)
		fmt.Fprintf(f, "%s\n", line)
	}
	f.Close()
	return os.Rename(tmp, s.path)
}
