// Package cidrban implements Python's sync_cidr_bans() logic:
// groups recent local bans by /24 subnet and auto-bans the entire /24
// in both Cloudflare and CrowdSec when 2+ distinct IPs are seen.
//
// Python constants:
//
//	CIDR_WINDOW     = 7 days
//	CIDR_THRESHOLD  = 2
//	CIDR_BAN_DURATION = "24h"
//	NOTE_TAG_CIDR   = "crowdsec-cidr-ban"
package cidrban

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

var ErrNotImplemented = errors.New("cidrban service not implemented yet")

const (
	cidrWindow      = 7 * 24 * time.Hour
	cidrThreshold   = 2
	cidrBanDuration = "24h"
	cidrBanExpiry   = 24 * time.Hour
	noteTagCIDR     = "crowdsec-cidr-ban"
)

// StateEntry records when a /24 was banned and how many distinct IPs triggered it.
type StateEntry struct {
	BannedAt time.Time `json:"banned_at"`
	IPCount  int       `json:"ip_count"`
}

// Record is kept for backward compat with existing callers.
type Record struct {
	IPs      []string  `json:"ips"`
	BannedAt time.Time `json:"banned_at"`
}

// Service is the CIDR ban contract.
type Service interface {
	Run(ctx context.Context) error
}

// Config groups injected dependencies.
type Config struct {
	StateDir string

	// BanSource provides recent local bans (7-day window).
	BanSource RecentBanSource

	// CFBanner adds a /24 IP range rule to Cloudflare.
	CFBanner CFBanner

	// CFRuleGetter lists existing CIDR rules (to detect already-banned /24s).
	CFRuleGetter CFRuleGetter

	// CFDeleter removes an expired CIDR rule.
	CFDeleter CFDeleter

	// CSRangeBanner adds a CrowdSec range decision via cscli.
	CSRangeBanner CSRangeBanner

	ZoneID string
}

type RecentBanSource interface {
	ListRecentBans(ctx context.Context) ([]Ban, error)
}

type Ban struct {
	IP   string
	When time.Time
}

type CFBanner interface {
	AddIPAccessRule(ctx context.Context, zoneID, cidr, notes, target string) (string, error)
}

type CFRuleGetter interface {
	ListIPAccessRulesByTag(ctx context.Context, zoneID, tag string) (map[string]string, error)
}

type CFDeleter interface {
	DeleteIPAccessRule(ctx context.Context, zoneID, ruleID string) error
}

type CSRangeBanner interface {
	AddRangeDecision(ctx context.Context, cidr, duration, reason string) error
}

// RealService implements sync_cidr_bans().
type RealService struct {
	cfg Config
}

// NewService creates a RealService. If cfg.BanSource is nil the service is a no-op.
func NewService(cfg Config) *RealService {
	return &RealService{cfg: cfg}
}

// PlaceholderService is the pre-parity stub.
type PlaceholderService struct{}

func NewPlaceholderService() *PlaceholderService { return &PlaceholderService{} }
func (s *PlaceholderService) Run(context.Context) error {
	return ErrNotImplemented
}

// Run executes one cycle of CIDR ban detection.
//
// Mirrors Python's sync_cidr_bans():
//  1. Read recent bans from decisions.log (CIDR_WINDOW = 7 days)
//  2. Group distinct IPs by /24 subnet
//  3. If ≥ CIDR_THRESHOLD (2) IPs → ban /24 24h in CF + CrowdSec
//  4. Expire /24 bans older than 24h
func (s *RealService) Run(ctx context.Context) error {
	if s.cfg.BanSource == nil {
		return nil
	}

	bans, err := s.cfg.BanSource.ListRecentBans(ctx)
	if err != nil {
		return fmt.Errorf("cidrban: ListRecentBans: %w", err)
	}
	if len(bans) == 0 {
		return nil
	}

	// Group distinct IPs by their /24 subnet.
	cidrIPs := make(map[string]map[string]bool)
	for _, ban := range bans {
		if ban.IP == "1.2.3.4" {
			continue
		}
		cidr24 := toCIDR24(ban.IP)
		if cidr24 == "" {
			continue
		}
		if cidrIPs[cidr24] == nil {
			cidrIPs[cidr24] = make(map[string]bool)
		}
		cidrIPs[cidr24][ban.IP] = true
	}

	state, _ := s.loadState()

	var cfCIDRRules map[string]string
	if s.cfg.CFRuleGetter != nil {
		cfCIDRRules, _ = s.cfg.CFRuleGetter.ListIPAccessRulesByTag(ctx, s.cfg.ZoneID, noteTagCIDR)
	}

	now := time.Now().UTC()
	changed := false

	for cidr, ips := range cidrIPs {
		if len(ips) < cidrThreshold {
			continue
		}
		if _, alreadyBanned := state[cidr]; alreadyBanned {
			// Already tracked; update ip_count if CF already has the rule.
			if cfCIDRRules != nil {
				if _, ok := cfCIDRRules[cidr]; ok {
					state[cidr] = StateEntry{BannedAt: state[cidr].BannedAt, IPCount: len(ips)}
				}
			}
			continue
		}
		// New /24 — ban in CF and CrowdSec.
		if _, ok := cfCIDRRules[cidr]; ok {
			// Already in CF (from a prior run). Record in state.
			state[cidr] = StateEntry{BannedAt: now, IPCount: len(ips)}
			changed = true
			continue
		}
		if s.cfg.CFBanner != nil {
			_, _ = s.cfg.CFBanner.AddIPAccessRule(ctx, s.cfg.ZoneID, cidr, noteTagCIDR, "ip_range")
		}
		if s.cfg.CSRangeBanner != nil {
			reason := fmt.Sprintf("auto-cidr-ban: %d IPs from %s", len(ips), cidr)
			_ = s.cfg.CSRangeBanner.AddRangeDecision(ctx, cidr, cidrBanDuration, reason)
		}
		state[cidr] = StateEntry{BannedAt: now, IPCount: len(ips)}
		changed = true
	}

	// Expire bans older than 24h and remove their CF rules.
	for cidr, entry := range state {
		if now.Sub(entry.BannedAt) < cidrBanExpiry {
			continue
		}
		if cfCIDRRules != nil {
			if ruleID, ok := cfCIDRRules[cidr]; ok && s.cfg.CFDeleter != nil {
				_ = s.cfg.CFDeleter.DeleteIPAccessRule(ctx, s.cfg.ZoneID, ruleID)
			}
		}
		delete(state, cidr)
		changed = true
	}

	if changed {
		_ = s.saveState(state)
	}
	return nil
}

// toCIDR24 returns the /24 containing ip (IPv4 only). Returns "" for IPv6 or invalid.
// Mirrors Python's get_cidr24().
func toCIDR24(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	ip = ip.To4()
	if ip == nil {
		return "" // IPv6 not supported (matches Python behavior)
	}
	_, network, err := net.ParseCIDR(fmt.Sprintf("%s/24", ipStr))
	if err != nil {
		return ""
	}
	return network.String()
}

func (s *RealService) stateFilePath() string {
	return filepath.Join(s.cfg.StateDir, "cidr-banned.json")
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
		return fmt.Errorf("cidrban saveState: %w", err)
	}
	return os.Rename(tmp, s.stateFilePath())
}
