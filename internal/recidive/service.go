// Package recidive implements Python's sync_recidivists() logic:
// monitors recent local bans, escalates repeat offenders via cscli.
//
// Python escalation table (RECIDIV_ESCALATION / RECIDIV_DEFAULT):
//
//	1st ban  → no escalation
//	2nd ban  → 24h
//	3rd+ ban → 168h (7 days)
package recidive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrNotImplemented = errors.New("recidive service not implemented yet")

// Python RECIDIV_WINDOW = 7 days
const recidivWindow = 7 * 24 * time.Hour

// Escalation durations. Python:
//
//	RECIDIV_ESCALATION = {0: None, 1: "24h"}
//	RECIDIV_DEFAULT    = "168h"
var escalationTable = map[int]string{
	1: "24h",
}

const escalationDefault = "168h"

// Record tracks the ban count and last observation for one IP.
// Mirrors Python's RecidivistEntry TypedDict.
type Record struct {
	Count    int       `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

// Service is the recidive tracking contract.
type Service interface {
	Run(ctx context.Context) error
}

// Config groups the dependencies injected at construction time.
type Config struct {
	StateDir string // directory for recidivists.json state file

	// BanSource reads recent bans from decisions.log.
	// Injected at construction; must not be nil for the real service to function.
	BanSource RecentBanSource

	// Escalator applies cscli decisions add.
	// Optional: if nil, escalation is logged but not applied (read-only mode).
	Escalator DecisionAdder
}

// RecentBanSource provides recently observed local bans.
type RecentBanSource interface {
	ListRecentBans(ctx context.Context) ([]Ban, error)
}

// DecisionAdder escalates a ban via cscli.
type DecisionAdder interface {
	AddIPDecision(ctx context.Context, ip, duration, reason string) error
}

// Ban is a single observed ban event, sourced from decisions.log.
type Ban struct {
	IP       string
	Scenario string
	When     time.Time
	ID       string
}

// RealService implements Python's sync_recidivists() with cursor-based deduplication.
type RealService struct {
	cfg Config
}

// NewService creates a RealService. If cfg.BanSource is nil the service is a no-op.
func NewService(cfg Config) *RealService {
	return &RealService{cfg: cfg}
}

// PlaceholderService is the pre-parity stub (kept for backward compat).
type PlaceholderService struct{}

func NewPlaceholderService() *PlaceholderService { return &PlaceholderService{} }
func (s *PlaceholderService) Run(context.Context) error {
	return ErrNotImplemented
}

// Run executes one cycle of recidivist detection and escalation.
//
// Mirrors Python's sync_recidivists():
//  1. Load recidivists.json state (with cursor to avoid double-counting)
//  2. Read recent bans from decisions.log (RECIDIV_WINDOW=7 days)
//  3. For bans after cursor: increment count, escalate if above threshold
//  4. Purge entries older than RECIDIV_WINDOW; save state
func (s *RealService) Run(ctx context.Context) error {
	if s.cfg.BanSource == nil {
		return nil // no-op when not wired
	}

	state, err := s.loadState()
	if err != nil {
		return fmt.Errorf("recidive: load state: %w", err)
	}

	bans, err := s.cfg.BanSource.ListRecentBans(ctx)
	if err != nil {
		return fmt.Errorf("recidive: ListRecentBans: %w", err)
	}
	if len(bans) == 0 {
		return nil
	}

	cursor, _ := parseTime(state["_cursor"])
	if cursor.IsZero() {
		cursor = time.Now().UTC()
	}
	newCursor := cursor
	changed := false

	for _, ban := range bans {
		if !ban.When.After(cursor) {
			continue
		}
		ip := ban.IP
		if ip == "1.2.3.4" || net.ParseIP(ip) == nil {
			continue
		}
		if strings.HasPrefix(ban.Scenario, "recidivist-escalation") {
			continue
		}
		if ban.When.After(newCursor) {
			newCursor = ban.When
		}

		var rec Record
		if existing, ok := state[ip]; ok {
			if err := json.Unmarshal([]byte(existing), &rec); err == nil {
				// Reset if last_seen is outside the window
				if time.Since(rec.LastSeen) > recidivWindow {
					rec = Record{}
				}
			}
		}
		rec.Count++
		rec.LastSeen = ban.When
		changed = true

		recBytes, _ := json.Marshal(rec)
		state[ip] = string(recBytes)

		// Determine escalation duration
		duration, ok := escalationTable[rec.Count-1]
		if !ok && rec.Count > 1 {
			duration = escalationDefault
		}
		if duration != "" && s.cfg.Escalator != nil {
			reason := fmt.Sprintf("Recidivist escalation | scenario: %s", ban.Scenario)
			if err := s.cfg.Escalator.AddIPDecision(ctx, ip, duration, reason); err != nil {
				// log only — non-fatal
				_ = err
			}
		}
	}

	if newCursor.After(cursor) {
		state["_cursor"] = newCursor.Format(time.RFC3339Nano)
	}
	if changed || newCursor.After(cursor) {
		_ = s.saveState(state)
	}
	return nil
}

// stateFilePath returns the path of recidivists.json.
func (s *RealService) stateFilePath() string {
	return filepath.Join(s.cfg.StateDir, "recidivists.json")
}

// loadState reads recidivists.json; returns empty map if file does not exist.
func (s *RealService) loadState() (map[string]string, error) {
	data, err := os.ReadFile(s.stateFilePath())
	if os.IsNotExist(err) {
		return make(map[string]string), nil
	}
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return make(map[string]string), nil
	}
	return m, nil
}

// saveState writes recidivists.json atomically.
func (s *RealService) saveState(state map[string]string) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.cfg.StateDir, 0755); err != nil {
		return err
	}
	tmp := s.stateFilePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.stateFilePath())
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, s)
}
