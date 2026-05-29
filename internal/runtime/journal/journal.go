package journal

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

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
	path string
	mu   sync.Mutex
}

func NewJSONLJournal(path string) *JSONLJournal {
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0755)
	return &JSONLJournal{
		path: path,
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
