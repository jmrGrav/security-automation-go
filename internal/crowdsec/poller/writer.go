package poller

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// DecisionRecord is a single line written to decisions.log.
// Must stay wire-compatible with the Python poller format.
type DecisionRecord struct {
	DT       string         `json:"dt"`
	Host     string         `json:"host"`
	Platform string         `json:"platform"`
	CS       decisionFields `json:"cs"`
}

type decisionFields struct {
	EventType   string `json:"event_type"`
	ID          int64  `json:"id"`
	IP          string `json:"ip"`
	Type        string `json:"type,omitempty"`
	Scenario    string `json:"scenario"`
	Duration    string `json:"duration,omitempty"`
	Origin      string `json:"origin,omitempty"`
	Scope       string `json:"scope,omitempty"`
	Simulated   bool   `json:"simulated,omitempty"`
	Action      string `json:"action,omitempty"`
	HasDecision bool   `json:"has_decision,omitempty"`
}

// logWriter appends newline-delimited JSON records to a file.
type logWriter struct {
	mu   sync.Mutex
	path string
}

func newLogWriter(path string) *logWriter { return &logWriter{path: path} }

func (w *logWriter) write(rec DecisionRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(w.path), 0o755); err != nil {
		return fmt.Errorf("log writer: mkdir: %w", err)
	}

	f, err := os.OpenFile(w.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("log writer: open: %w", err)
	}
	defer f.Close()

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("log writer: marshal: %w", err)
	}
	_, err = fmt.Fprintf(f, "%s\n", line)
	return err
}

// loadSeenIDs reads the log file and returns the set of IDs already recorded,
// split by event_type. Used at startup to avoid replaying old decisions.
func loadSeenIDs(path string) (decisionIDs map[int64]struct{}, alertIDs map[int64]struct{}, err error) {
	decisionIDs = make(map[int64]struct{})
	alertIDs = make(map[int64]struct{})

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return decisionIDs, alertIDs, nil
		}
		return nil, nil, fmt.Errorf("loadSeenIDs: open %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var rec struct {
			CS struct {
				EventType string `json:"event_type"`
				ID        int64  `json:"id"`
			} `json:"cs"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue // skip malformed lines
		}
		switch rec.CS.EventType {
		case "decision":
			decisionIDs[rec.CS.ID] = struct{}{}
		case "alert":
			alertIDs[rec.CS.ID] = struct{}{}
		}
	}
	return decisionIDs, alertIDs, sc.Err()
}
