// Package modsecurity implements Python's sync_modsec() logic:
// parses nginx error.log for ModSecurity Access denied events and bans
// qualifying IPs in Cloudflare.
//
// Python constants:
//
//	MODSEC_SCORE_MIN  = 5       (minimum anomaly score)
//	MODSEC_BAN_SECS   = 7200   (2h ban in CF)
//	LOOKBACK_HOURS    = 48
package modsecurity

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ErrNotImplemented = errors.New("modsecurity service not implemented yet")

// Python MODSEC_RE pattern.
var modsecRE = regexp.MustCompile(
	`\[client ([\d\.a-fA-F:]+)\] ModSecurity: Access denied.*?Total Score: (\d+).*?\[uri "([^"]+)"\]`,
)

// Python MODSEC_DATE_RE pattern.
var modsecDateRE = regexp.MustCompile(`(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})`)

const (
	modsecScoreMin = 5
	modsecBanSecs  = 7200 // 2h
	lookbackHours  = 48
)

// Event is a single ModSecurity access-denied event.
// Mirrors Python's ModsecEvent TypedDict.
type Event struct {
	IP    string
	Score int
	URI   string
	DT    time.Time
}

// StateEntry records when an IP was last banned via ModSec.
type StateEntry struct {
	BannedAt time.Time `json:"banned_at"`
	Score    int       `json:"score"`
	URI      string    `json:"uri"`
}

// Service is the ModSecurity sync contract.
type Service interface {
	Run(ctx context.Context) error
}

// Config groups injected dependencies.
type Config struct {
	NginxLogDir string // directory containing nginx error.log

	// CFBanner adds an IP access rule to Cloudflare.
	// Optional: if nil, bans are logged but not applied.
	CFBanner CFBanner

	StateDir string
}

// CFBanner adds an IP to Cloudflare (tag "modsec-ban", target "ip").
type CFBanner interface {
	AddIPAccessRule(ctx context.Context, zoneID, ip, notes, target string) (string, error)
}

// RealService implements sync_modsec().
type RealService struct {
	cfg Config
}

// NewService creates a RealService.
func NewService(cfg Config) *RealService {
	return &RealService{cfg: cfg}
}

// PlaceholderService is the pre-parity stub.
type PlaceholderService struct{}

func NewPlaceholderService() *PlaceholderService { return &PlaceholderService{} }
func (s *PlaceholderService) Run(context.Context) error {
	return ErrNotImplemented
}

// Run executes one cycle of ModSecurity event detection.
//
// Mirrors Python's sync_modsec():
//  1. Parse nginx error.log for ModSecurity Access denied with score >= 5
//  2. Skip IPs already banned within the 2h window
//  3. Add Cloudflare block rule (tag "modsec-ban")
//  4. Update state file
func (s *RealService) Run(ctx context.Context) error {
	logPath := filepath.Join(s.cfg.NginxLogDir, "error.log")
	events, err := parseModSecEvents(logPath)
	if err != nil || len(events) == 0 {
		return nil
	}

	state, _ := s.loadState()
	now := time.Now().UTC()

	// Deduplicate by IP, keep highest score.
	byIP := make(map[string]Event)
	for _, ev := range events {
		if existing, ok := byIP[ev.IP]; !ok || ev.Score > existing.Score {
			byIP[ev.IP] = ev
		}
	}

	changed := false
	for ip, ev := range byIP {
		if net.ParseIP(ip) == nil {
			continue
		}
		if entry, ok := state[ip]; ok {
			if now.Sub(entry.BannedAt).Seconds() < modsecBanSecs {
				continue
			}
		}
		if s.cfg.CFBanner != nil {
			// NOTE_TAG_MODSEC = "modsec-ban" — mirrors Python's NOTE_TAG_MODSEC.
			_, _ = s.cfg.CFBanner.AddIPAccessRule(ctx, "", ip, "modsec-ban", "ip")
		}
		state[ip] = StateEntry{
			BannedAt: now,
			Score:    ev.Score,
			URI:      ev.URI,
		}
		changed = true
	}

	// Expire entries older than 3h (modsecBanSecs + buffer).
	for ip, entry := range state {
		if now.Sub(entry.BannedAt).Seconds() >= modsecBanSecs*1.5 {
			delete(state, ip)
			changed = true
		}
	}

	if changed {
		_ = s.saveState(state)
	}
	return nil
}

// parseModSecEvents reads nginx error.log and extracts ModSecurity events.
// Mirrors Python's get_recent_modsec_events().
func parseModSecEvents(logPath string) ([]Event, error) {
	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	cutoff := time.Now().UTC().Add(-lookbackHours * time.Hour)
	var events []Event

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "ModSecurity: Access denied") || !strings.Contains(line, "Total Score:") {
			continue
		}
		dtMatch := modsecDateRE.FindString(line)
		if dtMatch == "" {
			continue
		}
		dt, err := time.ParseInLocation("2006/01/02 15:04:05", dtMatch, time.UTC)
		if err != nil || dt.Before(cutoff) {
			continue
		}
		m := modsecRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		score, _ := strconv.Atoi(m[2])
		if score < modsecScoreMin {
			continue
		}
		events = append(events, Event{
			IP:    m[1],
			Score: score,
			URI:   m[3],
			DT:    dt,
		})
	}
	return events, scanner.Err()
}

func (s *RealService) stateFilePath() string {
	return filepath.Join(s.cfg.StateDir, "modsec-banned.json")
}

func (s *RealService) loadState() (map[string]StateEntry, error) {
	data, err := os.ReadFile(s.stateFilePath())
	if os.IsNotExist(err) {
		return make(map[string]StateEntry), nil
	}
	if err != nil {
		return nil, err
	}
	var m map[string]StateEntry
	if err := json.Unmarshal(data, &m); err != nil {
		return make(map[string]StateEntry), nil
	}
	return m, nil
}

func (s *RealService) saveState(state map[string]StateEntry) error {
	data, _ := json.MarshalIndent(state, "", "  ")
	if err := os.MkdirAll(s.cfg.StateDir, 0755); err != nil {
		return err
	}
	tmp := s.stateFilePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("modsec saveState: %w", err)
	}
	return os.Rename(tmp, s.stateFilePath())
}
