package openrestyevent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLiveSourceReadsLuaEventsFile(t *testing.T) {
	dir := t.TempDir()
	eventsFile := filepath.Join(dir, "events.jsonl")
	content := `{"ts":1716800000.0,"type":"honeypot_hit","ip":"8.8.8.8","score":100,"detail":"/.env"}` + "\n"
	if err := os.WriteFile(eventsFile, []byte(content), 0644); err != nil {
		t.Fatalf("write events file: %v", err)
	}

	source := NewLiveSource(eventsFile)
	events, err := source.Read(context.Background())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].RuleID != "lua_honeypot" || events[0].URIs[0] != "/.env" {
		t.Fatalf("unexpected event: %+v", events[0])
	}
}

func TestLiveSourceIgnoresMalformedAndIncompleteLines(t *testing.T) {
	dir := t.TempDir()
	eventsFile := filepath.Join(dir, "events.jsonl")
	content := "" +
		`{"ts":1716800000.0,"type":"honeypot_hit","ip":"8.8.8.8","score":100,"detail":"/.env"}` + "\n" +
		`{"ts":1716800001.0,"type":"honeypot_hit","ip":"","score":100,"detail":"/wp-login.php"}` + "\n" +
		`not-json` + "\n"
	if err := os.WriteFile(eventsFile, []byte(content), 0644); err != nil {
		t.Fatalf("write events file: %v", err)
	}

	source := NewLiveSource(eventsFile)
	events, err := source.Read(context.Background())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one valid event, got %d", len(events))
	}
	if events[0].IP != "8.8.8.8" || events[0].URIs[0] != "/.env" {
		t.Fatalf("unexpected event: %+v", events[0])
	}
}

func TestLiveSourceRecoversStaleProcFile(t *testing.T) {
	dir := t.TempDir()
	eventsFile := filepath.Join(dir, "events.jsonl")
	procFile := filepath.Join(dir, "events.processing")

	// Simulate a crash: .processing file exists with unprocessed events, no main events file.
	stale := `{"ts":1716800000.0,"type":"honeypot_hit","ip":"1.2.3.4","score":100,"detail":"/stale"}` + "\n"
	if err := os.WriteFile(procFile, []byte(stale), 0644); err != nil {
		t.Fatalf("write proc file: %v", err)
	}

	source := NewLiveSource(eventsFile)
	events, err := source.Read(context.Background())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 recovered event, got %d", len(events))
	}
	if events[0].IP != "1.2.3.4" {
		t.Fatalf("unexpected IP: %s", events[0].IP)
	}
	if _, err := os.Stat(procFile); !os.IsNotExist(err) {
		t.Fatalf("stale .processing file should be removed after recovery")
	}
}

func TestLiveSourceNewEventsOverrideAfterStaleProcRemoved(t *testing.T) {
	dir := t.TempDir()
	eventsFile := filepath.Join(dir, "events.jsonl")
	procFile := filepath.Join(dir, "events.processing")

	// Stale .processing exists but is empty/unreadable.
	if err := os.WriteFile(procFile, []byte(""), 0644); err != nil {
		t.Fatalf("write empty proc file: %v", err)
	}
	// New events file also exists.
	fresh := `{"ts":1716800001.0,"type":"lua_heuristic","ip":"5.6.7.8","score":50,"detail":"/fresh"}` + "\n"
	if err := os.WriteFile(eventsFile, []byte(fresh), 0644); err != nil {
		t.Fatalf("write events file: %v", err)
	}

	source := NewLiveSource(eventsFile)
	events, err := source.Read(context.Background())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(events) != 1 || events[0].IP != "5.6.7.8" {
		t.Fatalf("expected fresh event from events file, got %+v", events)
	}
}
