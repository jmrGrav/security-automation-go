package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/jm/security-automation-go/internal/cidrban"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/crowdsec"
	csmodels "github.com/jm/security-automation-go/internal/crowdsec/models"
	luastate "github.com/jm/security-automation-go/internal/openresty/state"
	"github.com/jm/security-automation-go/internal/recidive"
	"github.com/jm/security-automation-go/internal/security/protected"
)

// allowlistSet is a compiled view of the CrowdSec allowlist for fast lookup.
// Mirrors Python's is_allowlisted(): direct IP match, then CIDR coverage.
type allowlistSet struct {
	ips  map[string]bool // normalized IP string → bool
	nets []*net.IPNet    // CIDR entries from the allowlist
}

func newAllowlistSet(entries []csmodels.AllowlistEntry) *allowlistSet {
	s := &allowlistSet{ips: make(map[string]bool)}
	for _, e := range entries {
		if ip := net.ParseIP(e.Value); ip != nil {
			s.ips[ip.String()] = true
		} else if _, cidr, err := net.ParseCIDR(e.Value); err == nil {
			s.nets = append(s.nets, cidr)
		}
	}
	return s
}

// contains mirrors Python's is_allowlisted(): direct IP match then CIDR coverage.
// Returns false if ipStr is not a valid IP (Python: except ValueError: pass).
func (s *allowlistSet) contains(ipStr string) bool {
	if s == nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if s.ips[ip.String()] {
		return true
	}
	for _, cidr := range s.nets {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// asMap returns the direct-IP entries as a map[string]bool for the drift classifier.
// CIDR-allowlisted IPs that appear as drift strings are not expanded here.
func (s *allowlistSet) asMap() map[string]bool {
	if s == nil {
		return nil
	}
	return s.ips
}

// fetchAllowlist retrieves the CrowdSec allowlist for the current cycle.
// Fail-open on error: returns nil (no filter applied), matching Python's
// circuit-breaker behavior which returns set() on failure.
func (a *CrowdSecSyncApp) fetchAllowlist(ctx context.Context) *allowlistSet {
	if a.csAllowlist == nil {
		return nil
	}
	entries, err := a.csAllowlist.ListAllowlist(ctx, a.cfg.CrowdSec.AllowlistName)
	if err != nil {
		a.logger.WarnContext(ctx, "allowlist fetch failed (fail-open)",
			"name", a.cfg.CrowdSec.AllowlistName, "error", err)
		return nil
	}
	return newAllowlistSet(entries)
}

// newLuaWriter creates a luastate.Writer from config, or nil if push is disabled.
func newLuaWriter(cfg *config.Config) *luastate.Writer {
	if !cfg.OpenResty.LuaStatePushEnable {
		return nil
	}
	hostname, _ := os.Hostname()
	return luastate.New(luastate.Config{
		Path:       cfg.OpenResty.LuaStatePath,
		ShadowPath: cfg.OpenResty.ShadowLuaStatePath,
		Hostname:   hostname,
		PID:        os.Getpid(),
	})
}

// pushLuaState writes bans.json for the OpenResty Lua bouncer.
// Source: active CrowdSec bans + active CIDR bans from cidrban state.
// Applies shield + allowlist filters. Skipped if luaWriter is nil.
func (a *CrowdSecSyncApp) pushLuaState(ctx context.Context, logger *slog.Logger) {
	if a.luaWriter == nil {
		return
	}

	bans, err := a.cs.ListActiveBans(ctx)
	if err != nil {
		logger.WarnContext(ctx, "lua state push: ListActiveBans failed (skip)", "error", err)
		return
	}

	// Load allowlist for the filter.
	allowlist := a.fetchAllowlist(ctx)
	filter := luastate.FilterFunc(func(ip string) bool {
		if a.shield != nil && a.shield.IsProtected(ip) {
			return true
		}
		return allowlist.contains(ip)
	})

	// Read active CIDR bans from cidrban state file.
	cidrs := loadActiveCIDRs(a.cfg.StateDir)

	if err := a.luaWriter.Write(ctx, bans, cidrs, filter); err != nil {
		logger.WarnContext(ctx, "lua state push failed (non-fatal)", "error", err)
	}
}

// loadActiveCIDRs reads the cidrban state file and returns non-expired /24 entries.
func loadActiveCIDRs(stateDir string) []string {
	data, err := os.ReadFile(filepath.Join(stateDir, "cidr-banned.json"))
	if err != nil {
		return nil
	}
	var m map[string]struct {
		BannedAt string `json:"banned_at"`
		IPCount  int    `json:"ip_count"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	expiry := 24 * time.Hour
	now := time.Now().UTC()
	var cidrs []string
	for cidr, entry := range m {
		t, err := time.Parse(time.RFC3339Nano, entry.BannedAt)
		if err != nil {
			t, err = time.Parse(time.RFC3339, entry.BannedAt)
		}
		if err == nil && now.Sub(t.UTC()) < expiry {
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs
}

// cidrBanSourceAdapter adapts crowdsec.ActiveBanSource → cidrban.RecentBanSource.
//
// Applies both the anti-self-ban shield and the CrowdSec allowlist filter,
// mirroring Python's sync_cidr_bans() which calls is_protected() and
// is_allowlisted() before grouping IPs by /24.
type cidrBanSourceAdapter struct {
	src           crowdsec.ActiveBanSource
	shield        *protected.Shield
	csAllowlist   crowdsec.AllowlistManager // nil → no allowlist filter
	allowlistName string
}

func (a *cidrBanSourceAdapter) ListRecentBans(ctx context.Context) ([]cidrban.Ban, error) {
	bans, err := a.src.ListRecentBans(ctx)
	if err != nil {
		return nil, err
	}

	// Fetch allowlist for this CIDR cycle (mirrors Python's cs_allowlist parameter).
	// Fail-open on error: nil allowlist means no IPs are filtered.
	var al *allowlistSet
	if a.csAllowlist != nil {
		entries, alErr := a.csAllowlist.ListAllowlist(ctx, a.allowlistName)
		if alErr == nil {
			al = newAllowlistSet(entries)
		}
	}

	out := make([]cidrban.Ban, 0, len(bans))
	for _, b := range bans {
		if a.shield != nil && a.shield.IsProtected(b.IP) {
			continue // P0: never count a protected IP
		}
		if al.contains(b.IP) {
			continue // Allowlist: mirrors Python's is_allowlisted() check
		}
		out = append(out, cidrban.Ban{IP: b.IP, When: b.When})
	}
	return out, nil
}

// recidiveBanSourceAdapter adapts crowdsec.ActiveBanSource → recidive.RecentBanSource.
// Applies shield and allowlist filters identically to cidrBanSourceAdapter so that
// the same protections apply to recidive tracking as to CIDR aggregation.
// crowdsec.Client.ListRecentBans() already filters by LOCAL_ORIGINS; no extra origin filter needed.
type recidiveBanSourceAdapter struct {
	src           crowdsec.ActiveBanSource
	shield        *protected.Shield
	csAllowlist   crowdsec.AllowlistManager
	allowlistName string
}

func (a *recidiveBanSourceAdapter) ListRecentBans(ctx context.Context) ([]recidive.Ban, error) {
	bans, err := a.src.ListRecentBans(ctx)
	if err != nil {
		return nil, err
	}
	var al *allowlistSet
	if a.csAllowlist != nil {
		entries, alErr := a.csAllowlist.ListAllowlist(ctx, a.allowlistName)
		if alErr == nil {
			al = newAllowlistSet(entries)
		}
	}
	out := make([]recidive.Ban, 0, len(bans))
	for _, b := range bans {
		if a.shield != nil && a.shield.IsProtected(b.IP) {
			continue
		}
		if al.contains(b.IP) {
			continue
		}
		out = append(out, recidive.Ban{IP: b.IP, Scenario: b.Scenario, When: b.When, ID: b.ID})
	}
	return out, nil
}
