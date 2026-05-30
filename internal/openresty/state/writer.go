// Package state writes the OpenResty/Lua enforcement state file (bans.json).
//
// Python equivalent: push_lua_state() in crowdsec-cf-sync V4.
//
// The Lua bouncer (access.lua) reads /run/crowdsec-lua/bans.json every 5s.
// Go writes a compatible JSON payload atomically (tmpfile + rename) so the
// Lua reader never observes a partial write.
//
// In shadow mode the writer targets an alternate path (or is a no-op) so that
// Python's production bans.json is never overwritten while Python still runs.
package state

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"time"
)

// BanEntry mirrors Python's LuaBanEntry TypedDict.
type BanEntry struct {
	Score  int    `json:"score"`
	Level  int    `json:"level"`
	TTL    int    `json:"ttl"`
	Reason string `json:"reason"`
}

// Payload mirrors the top-level structure of Python's push_lua_state() output.
// Fields that OpenResty Lua reads are preserved; operational meta is included
// for compatibility with the existing Lua status/metrics endpoint.
type Payload struct {
	Version        int                 `json:"version"`
	UpdatedAt      string              `json:"updated_at"`
	UpdatedAtEpoch int64               `json:"updated_at_epoch"`
	EntryCount     int                 `json:"entry_count"`
	WriterPID      int                 `json:"writer_pid"`
	WriterHostname string              `json:"writer_hostname"`
	Bans           map[string]BanEntry `json:"bans"`
	CIDRs          map[string]BanEntry `json:"cidrs"`
	Meta           map[string]any      `json:"meta"`
	PayloadCRC32   uint32              `json:"payload_crc32"`
}

// BanSource provides the active CrowdSec IP bans for Lua state construction.
type BanSource interface {
	ListActiveBans(ctx context.Context) ([]string, error)
}

// CIDRSource provides the active /24 CIDR bans from the cidrban state file.
type CIDRSource interface {
	// ListActiveCIDRs returns CIDR strings currently banned.
	ListActiveCIDRs(ctx context.Context) ([]string, error)
}

// Filter decides whether an IP should be excluded from the Lua state.
// Typically combines anti-self-ban shield + CrowdSec allowlist.
type Filter interface {
	ShouldExclude(ip string) bool
}

// FilterFunc is a function that satisfies Filter.
type FilterFunc func(ip string) bool

func (f FilterFunc) ShouldExclude(ip string) bool { return f(ip) }

// Config controls the writer's behaviour.
type Config struct {
	// Path is the real bans.json path (e.g. /run/crowdsec-lua/bans.json).
	// Required in live mode; ignored in shadow mode if ShadowPath is set.
	Path string

	// ShadowPath is the alternate path used in shadow mode.
	// If empty in shadow mode, the writer is a no-op.
	ShadowPath string

	// ShadowMode suppresses writes to Path; uses ShadowPath instead.
	ShadowMode bool

	// Hostname and PID are included in the payload for debugging.
	Hostname string
	PID      int
}

// Writer produces bans.json from live CrowdSec state.
type Writer struct {
	cfg     Config
	version int
}

// New creates a Writer.
func New(cfg Config) *Writer {
	return &Writer{cfg: cfg}
}

// Write builds and atomically writes bans.json.
// In shadow mode it writes to ShadowPath (or is a no-op if ShadowPath is empty).
// Applies the supplied filter to exclude protected/allowlisted IPs.
func (w *Writer) Write(ctx context.Context, bans []string, cidrs []string, filter Filter) error {
	targetPath := w.cfg.Path
	if w.cfg.ShadowMode {
		if w.cfg.ShadowPath == "" {
			return nil // shadow mode, no shadow path configured → no-op
		}
		targetPath = w.cfg.ShadowPath
	}
	if targetPath == "" {
		return nil
	}

	w.version++
	now := time.Now().UTC()

	banMap := make(map[string]BanEntry, len(bans))
	for _, ip := range bans {
		if filter != nil && filter.ShouldExclude(ip) {
			continue
		}
		banMap[ip] = BanEntry{Score: 70, Level: 5, TTL: 3600, Reason: "crowdsec-ban"}
	}

	cidrMap := make(map[string]BanEntry, len(cidrs))
	for _, cidr := range cidrs {
		cidrMap[cidr] = BanEntry{Score: 100, Level: 5, TTL: 86400, Reason: "crowdsec-cidr"}
	}

	payload := Payload{
		Version:        w.version,
		UpdatedAt:      now.Format(time.RFC3339Nano),
		UpdatedAtEpoch: now.Unix(),
		EntryCount:     len(banMap) + len(cidrMap),
		WriterPID:      w.cfg.PID,
		WriterHostname: w.cfg.Hostname,
		Bans:           banMap,
		CIDRs:          cidrMap,
		Meta:           map[string]any{"writer": "go-crowdsec-sync"},
	}

	// Compute CRC32 of payload-without-crc32 for Lua integrity check.
	preBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("openresty/state: marshal payload: %w", err)
	}
	payload.PayloadCRC32 = crc32.ChecksumIEEE(preBytes)

	finalBytes, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("openresty/state: marshal final: %w", err)
	}

	return atomicWrite(targetPath, finalBytes)
}

// atomicWrite writes data to path using a temp file + rename.
// This matches Python's atomic write approach and prevents partial reads by Lua.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("openresty/state: mkdir: %w", err)
	}

	f, err := os.CreateTemp(dir, ".bans-*.tmp")
	if err != nil {
		return fmt.Errorf("openresty/state: create temp: %w", err)
	}
	tmp := f.Name()

	// Set permissions before writing so the Lua www-data user can read it.
	if err := f.Chmod(0644); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("openresty/state: chmod: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("openresty/state: write: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("openresty/state: fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("openresty/state: close: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("openresty/state: rename: %w", err)
	}
	return nil
}
