package journal

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

// JournalStore is an append-only auditor.
type JournalStore interface {
	Append(event models.AuditEvent) error
	List() ([]models.AuditEvent, error)
}

// JSONLJournal implements JournalStore using a line-delimited JSON file.
type JSONLJournal struct {
	path        string
	mu          sync.Mutex
	retention   time.Duration
	maxEntries  int
	pruneEvery  int
	maxBytes    int64
	appendCount int
	lastPrune   time.Time
	now         func() time.Time
}

func NewJSONLJournal(path string) *JSONLJournal {
	return NewJSONLJournalWithPolicy(path, 180*24*time.Hour, 100_000, 256, 8<<20)
}

func NewJSONLJournalWithPolicy(path string, retention time.Duration, maxEntries int, pruneEvery int, maxBytes int64) *JSONLJournal {
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0755)
	if retention <= 0 {
		retention = 180 * 24 * time.Hour
	}
	if maxEntries <= 0 {
		maxEntries = 100_000
	}
	if pruneEvery <= 0 {
		pruneEvery = 256
	}
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	return &JSONLJournal{
		path:       path,
		retention:  retention,
		maxEntries: maxEntries,
		pruneEvery: pruneEvery,
		maxBytes:   maxBytes,
		now:        time.Now,
	}
}

func (j *JSONLJournal) Append(event models.AuditEvent) error {
	const op = "runtime.journal.Append"

	data, err := json.Marshal(event)
	if err != nil {
		return apperr.Wrap(op, err)
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	f, err := os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	defer f.Close()

	if _, err := f.Write(append(data, '\n')); err != nil {
		return apperr.Wrap(op, err)
	}
	j.appendCount++
	if err := j.maybePruneLocked(); err != nil {
		return err
	}

	return nil
}

// List returns all audit events from the journal.
func (j *JSONLJournal) List() ([]models.AuditEvent, error) {
	const op = "runtime.journal.List"

	j.mu.Lock()
	defer j.mu.Unlock()

	f, err := os.Open(j.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, apperr.Wrap(op, err)
	}
	defer f.Close()

	var events []models.AuditEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var event models.AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		events = append(events, event)
	}

	return events, apperr.Wrap(op, scanner.Err())
}

func (j *JSONLJournal) maybePruneLocked() error {
	if j == nil {
		return nil
	}
	now := j.now()
	shouldPrune := j.pruneEvery > 0 && j.appendCount%j.pruneEvery == 0
	if !shouldPrune {
		if info, err := os.Stat(j.path); err == nil && j.maxBytes > 0 && info.Size() > j.maxBytes {
			shouldPrune = true
		}
	}
	if !shouldPrune && !j.lastPrune.IsZero() && now.Sub(j.lastPrune) < 5*time.Minute {
		return nil
	}
	if err := j.pruneLocked(now); err != nil {
		return err
	}
	j.lastPrune = now
	return nil
}

func (j *JSONLJournal) pruneLocked(now time.Time) error {
	const op = "runtime.journal.Prune"

	raw, err := os.ReadFile(j.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return apperr.Wrap(op, err)
	}

	type lineEntry struct {
		raw    string
		ts     time.Time
		parsed bool
	}
	lines := bufio.NewScanner(bytes.NewReader(raw))
	var entries []lineEntry
	for lines.Scan() {
		line := lines.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event models.AuditEvent
		entry := lineEntry{raw: line}
		if err := json.Unmarshal([]byte(line), &event); err == nil {
			entry.ts = event.Timestamp.UTC()
			entry.parsed = true
		}
		entries = append(entries, entry)
	}
	if err := lines.Err(); err != nil {
		return apperr.Wrap(op, err)
	}
	if len(entries) == 0 {
		return nil
	}

	kept := entries[:0]
	cutoff := now.Add(-j.retention)
	for _, entry := range entries {
		if entry.parsed && !entry.ts.IsZero() && entry.ts.Before(cutoff) {
			continue
		}
		kept = append(kept, entry)
	}
	if j.maxEntries > 0 && len(kept) > j.maxEntries {
		kept = kept[len(kept)-j.maxEntries:]
	}
	if len(kept) == len(entries) {
		return nil
	}

	tmp, err := os.CreateTemp(filepath.Dir(j.path), filepath.Base(j.path)+".*.tmp")
	if err != nil {
		return apperr.Wrap(op, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	defer cleanup()
	writer := bufio.NewWriter(tmp)
	for _, entry := range kept {
		if _, err := writer.WriteString(entry.raw); err != nil {
			return apperr.Wrap(op, err)
		}
		if err := writer.WriteByte('\n'); err != nil {
			return apperr.Wrap(op, err)
		}
	}
	if err := writer.Flush(); err != nil {
		return apperr.Wrap(op, err)
	}
	if err := tmp.Close(); err != nil {
		return apperr.Wrap(op, err)
	}
	if err := os.Rename(tmpPath, j.path); err != nil {
		return apperr.Wrap(op, err)
	}
	return nil
}
