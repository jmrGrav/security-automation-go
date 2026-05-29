// Package lua defines the versioned contract boundary for the OpenResty Lua
// mitigation layer. It intentionally does not read live nginx files or mutate
// the runtime; it only validates normalized configuration and emits internal
// adapter events.
package lua

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/events"
)

const SchemaVersion = "v1"

type Contract struct {
	SchemaVersion    string `json:"schema_version"`
	SyncDir          string `json:"sync_dir"`
	SyncFile         string `json:"sync_file"`
	EventsFile       string `json:"events_file"`
	FailOpen         bool   `json:"fail_open"`
	SyncIntervalSecs int    `json:"sync_interval_seconds"`
	HeuristicTTLSecs int    `json:"heuristic_ttl_seconds"`
	BurstWindowSecs  int    `json:"burst_window_seconds"`
	BurstThreshold   int    `json:"burst_threshold"`
	DeadmanSecs      int    `json:"deadman_seconds"`
	MaxTarpits       int    `json:"max_tarpits"`
	MemoryPressure   int    `json:"memory_pressure_percent"`
}

type Summary struct {
	IPCContract string `json:"ipc_contract"`
	FailMode    string `json:"fail_mode"`
}

type RenderedBundle struct {
	ContractJSON string `json:"contract_json"`
	SummaryText  string `json:"summary_text"`
}

func Parse(data []byte) (Contract, error) {
	var cfg Contract

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Contract{}, fmt.Errorf("decode lua contract: %w", err)
	}
	if dec.More() {
		return Contract{}, errors.New("decode lua contract: trailing JSON content")
	}
	if err := Validate(cfg); err != nil {
		return Contract{}, err
	}
	return cfg, nil
}

func Validate(cfg Contract) error {
	if cfg.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported lua schema version %q", cfg.SchemaVersion)
	}
	if strings.TrimSpace(cfg.SyncDir) == "" {
		return errors.New("lua sync_dir is required")
	}
	if strings.TrimSpace(cfg.SyncFile) == "" {
		return errors.New("lua sync_file is required")
	}
	if strings.TrimSpace(cfg.EventsFile) == "" {
		return errors.New("lua events_file is required")
	}
	if filepath.Dir(cfg.SyncFile) != filepath.Clean(cfg.SyncDir) {
		return errors.New("lua sync_file must reside under sync_dir")
	}
	if filepath.Dir(cfg.EventsFile) != filepath.Clean(cfg.SyncDir) {
		return errors.New("lua events_file must reside under sync_dir")
	}
	if cfg.SyncIntervalSecs <= 0 {
		return errors.New("lua sync_interval_seconds must be positive")
	}
	if cfg.HeuristicTTLSecs <= 0 {
		return errors.New("lua heuristic_ttl_seconds must be positive")
	}
	if cfg.BurstWindowSecs <= 0 {
		return errors.New("lua burst_window_seconds must be positive")
	}
	if cfg.BurstThreshold <= 0 {
		return errors.New("lua burst_threshold must be positive")
	}
	if cfg.DeadmanSecs <= 0 {
		return errors.New("lua deadman_seconds must be positive")
	}
	if cfg.MaxTarpits < 0 {
		return errors.New("lua max_tarpits must not be negative")
	}
	if cfg.MemoryPressure < 1 || cfg.MemoryPressure > 100 {
		return errors.New("lua memory_pressure_percent must be between 1 and 100")
	}
	return nil
}

func Summarize(cfg Contract) Summary {
	failMode := "fail_closed"
	if cfg.FailOpen {
		failMode = "fail_open"
	}
	return Summary{
		IPCContract: filepath.Base(cfg.SyncFile) + "|" + filepath.Base(cfg.EventsFile),
		FailMode:    failMode,
	}
}

func RuntimeEvents(_ context.Context, cfg Contract, scopeID, correlationID string, now time.Time) []events.PublishRequest {
	ts := now.UTC()
	summary := Summarize(cfg)

	meta := map[string]any{
		"adapter":                 "lua",
		"schema_version":          cfg.SchemaVersion,
		"ipc_contract":            summary.IPCContract,
		"fail_mode":               summary.FailMode,
		"sync_interval_seconds":   cfg.SyncIntervalSecs,
		"heuristic_ttl_seconds":   cfg.HeuristicTTLSecs,
		"burst_window_seconds":    cfg.BurstWindowSecs,
		"burst_threshold":         cfg.BurstThreshold,
		"deadman_seconds":         cfg.DeadmanSecs,
		"memory_pressure_percent": cfg.MemoryPressure,
	}

	return []events.PublishRequest{
		{
			Timestamp:     ts,
			Category:      events.CategorySecurity,
			Type:          "lua_contract_loaded",
			CorrelationID: correlationID,
			Actor:         "adapter/lua",
			ScopeID:       scopeID,
			Payload: map[string]any{
				"sync_dir":    cfg.SyncDir,
				"sync_file":   cfg.SyncFile,
				"events_file": cfg.EventsFile,
			},
			Metadata: meta,
		},
		{
			Timestamp:     ts,
			Category:      events.CategorySecurity,
			Type:          "lua_fail_mode_declared",
			CorrelationID: correlationID,
			Actor:         "adapter/lua",
			ScopeID:       scopeID,
			Payload: map[string]any{
				"fail_open": cfg.FailOpen,
			},
			Metadata: meta,
		},
	}
}

func RenderDryRun(cfg Contract) (RenderedBundle, error) {
	if err := Validate(cfg); err != nil {
		return RenderedBundle{}, err
	}
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return RenderedBundle{}, fmt.Errorf("render lua contract: %w", err)
	}
	return RenderedBundle{
		ContractJSON: string(body) + "\n",
		SummaryText: fmt.Sprintf(
			"sync_dir=%s sync_file=%s events_file=%s fail_open=%t sync_interval_seconds=%d deadman_seconds=%d memory_pressure_percent=%d",
			cfg.SyncDir,
			cfg.SyncFile,
			cfg.EventsFile,
			cfg.FailOpen,
			cfg.SyncIntervalSecs,
			cfg.DeadmanSecs,
			cfg.MemoryPressure,
		),
	}, nil
}
