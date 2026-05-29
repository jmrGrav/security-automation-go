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
	if _, err := os.Stat(s.EventsFile); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	procFile := strings.TrimSuffix(s.EventsFile, filepath.Ext(s.EventsFile)) + ".processing"
	if err := os.Rename(s.EventsFile, procFile); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = os.Remove(procFile) }()

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
