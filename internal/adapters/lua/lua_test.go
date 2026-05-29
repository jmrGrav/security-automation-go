package lua

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAndRuntimeEvents(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "contract.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	now := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
	evs := RuntimeEvents(context.Background(), cfg, "scope-a", "corr-2", now)
	if len(evs) != 2 {
		t.Fatalf("unexpected event count: %d", len(evs))
	}
	if evs[1].Type != "lua_fail_mode_declared" {
		t.Fatalf("unexpected second event type: %s", evs[1].Type)
	}
}

func TestRenderDryRun(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "contract.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rendered, err := RenderDryRun(cfg)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(rendered.ContractJSON, `"sync_dir": "/run/crowdsec-lua"`) {
		t.Fatalf("unexpected contract json:\n%s", rendered.ContractJSON)
	}
}

func TestValidateRejectsOutOfTreeFiles(t *testing.T) {
	cfg := Contract{
		SchemaVersion:    SchemaVersion,
		SyncDir:          "/run/crowdsec-lua",
		SyncFile:         "/tmp/bans.json",
		EventsFile:       "/run/crowdsec-lua/events.jsonl",
		SyncIntervalSecs: 5,
		HeuristicTTLSecs: 10,
		BurstWindowSecs:  5,
		BurstThreshold:   1,
		DeadmanSecs:      1,
		MaxTarpits:       0,
		MemoryPressure:   50,
	}

	if err := Validate(cfg); err == nil {
		t.Fatal("expected sync_file directory validation error")
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	data := []byte(`{
		"schema_version":"v1",
		"sync_dir":"/run/crowdsec-lua",
		"sync_file":"/run/crowdsec-lua/bans.json",
		"events_file":"/run/crowdsec-lua/events.jsonl",
		"fail_open":true,
		"sync_interval_seconds":5,
		"heuristic_ttl_seconds":7200,
		"burst_window_seconds":60,
		"burst_threshold":120,
		"deadman_seconds":120,
		"max_tarpits":20,
		"memory_pressure_percent":90,
		"extra":true
	}`)

	if _, err := Parse(data); err == nil {
		t.Fatal("expected unknown field error")
	}
}
