package quarantine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
)

type Store struct {
	dir string
}

func New(dir string) *Store {
	return &Store{dir: dir}
}

// Quarantine moves an object to the quarantine directory for manual review.
func (s *Store) Quarantine(id string, reason string, artifact interface{}) error {
	const op = "runtime.quarantine.Quarantine"

	if err := os.MkdirAll(s.dir, 0755); err != nil {
		return apperr.Wrap(op, err)
	}

	entry := struct {
		ID        string      `json:"id"`
		Reason    string      `json:"reason"`
		Timestamp time.Time   `json:"quarantined_at"`
		Artifact  interface{} `json:"artifact"`
	}{
		ID:        id,
		Reason:    reason,
		Timestamp: time.Now().UTC(),
		Artifact:  artifact,
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return apperr.Wrap(op, err)
	}

	filename := fmt.Sprintf("%s_%s.json", entry.Timestamp.Format("20060102_150405"), id)
	path := filepath.Join(s.dir, filename)

	return apperr.Wrap(op, os.WriteFile(path, data, 0644))
}
