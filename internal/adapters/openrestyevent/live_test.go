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
