package openrestyevent

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type LiveSource struct {
	EventsFile string
}

func NewLiveSource(eventsFile string) *LiveSource {
	return &LiveSource{EventsFile: eventsFile}
}

type luaEvent struct {
	TS     float64 `json:"ts"`
	Type   string  `json:"type"`
	IP     string  `json:"ip"`
	Score  int     `json:"score"`
	Detail string  `json:"detail"`
}

func (s *LiveSource) Read(ctx context.Context) ([]RawEvent, error) {
	_ = ctx
	if s == nil || strings.TrimSpace(s.EventsFile) == "" {
		return nil, nil
	}
	procFile := strings.TrimSuffix(s.EventsFile, filepath.Ext(s.EventsFile)) + ".processing"

	// Recover any stale .processing file left by a prior crash before checking for new events.
	// On Linux, os.Rename overwrites an existing destination, so without this check a new
	// events file would silently overwrite the stale one, losing the previous batch.
	if _, err := os.Stat(procFile); err == nil {
		events, parseErr := s.parseProcessingFile(procFile)
		_ = os.Remove(procFile) // always remove: either consumed successfully or unrecoverable
		if parseErr == nil && len(events) > 0 {
			return events, nil
		}
	}

	if _, err := os.Stat(s.EventsFile); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if err := os.Rename(s.EventsFile, procFile); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	events, err := s.parseProcessingFile(procFile)
	_ = os.Remove(procFile)
	return events, err
}

func (s *LiveSource) parseProcessingFile(procFile string) ([]RawEvent, error) {
	f, err := os.Open(procFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	events := make([]RawEvent, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev luaEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if strings.TrimSpace(ev.IP) == "" || strings.TrimSpace(ev.Detail) == "" {
			continue
		}
		ts := time.Unix(int64(ev.TS), int64((ev.TS-float64(int64(ev.TS)))*1e9)).UTC()
		ruleID := "lua_heuristic"
		ruleName := ev.Type
		if ev.Type == "honeypot_hit" {
			ruleID = "lua_honeypot"
		}
		events = append(events, RawEvent{
			IP:        ev.IP,
			URIs:      []string{ev.Detail},
			Action:    "block",
			RuleID:    ruleID,
			RuleName:  ruleName,
			Timestamp: ts,
			Hits:      1,
			WindowSec: 300,
		})
	}
	return events, scanner.Err()
}
