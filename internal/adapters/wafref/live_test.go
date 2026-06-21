package wafref

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLiveSourceReadsRefsFile(t *testing.T) {
	dir := t.TempDir()
	refsFile := filepath.Join(dir, "waf_refs.jsonl")
	content := `{"ref":"1A2B3C-DEF012","ts":"2026-06-13T10:00:00Z","client_ip":"8.8.8.8","host":"arleo.eu","method":"GET","uri":"/?q=<script>alert(1)</script>","reason":"appsec"}` + "\n"
	if err := os.WriteFile(refsFile, []byte(content), 0644); err != nil {
		t.Fatalf("write refs file: %v", err)
	}

	source := NewLiveSource(refsFile)
	events, err := source.Read(context.Background())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].Ref != "1A2B3C-DEF012" || events[0].IP != "8.8.8.8" {
		t.Fatalf("unexpected event: %+v", events[0])
	}
	if events[0].Timestamp.IsZero() {
		t.Fatal("expected parsed timestamp")
	}
}

func TestLiveSourceIgnoresMalformedAndIncompleteLines(t *testing.T) {
	dir := t.TempDir()
	refsFile := filepath.Join(dir, "waf_refs.jsonl")
	content := "" +
		`{"ref":"REF1","ts":"2026-06-13T10:00:00Z","client_ip":"8.8.8.8","uri":"/a"}` + "\n" +
		`{"ref":"","ts":"2026-06-13T10:00:01Z","client_ip":"9.9.9.9","uri":"/b"}` + "\n" +
		`not-json` + "\n"
	if err := os.WriteFile(refsFile, []byte(content), 0644); err != nil {
		t.Fatalf("write refs file: %v", err)
	}

	source := NewLiveSource(refsFile)
	events, err := source.Read(context.Background())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one valid event, got %d", len(events))
	}
	if events[0].Ref != "REF1" {
		t.Fatalf("unexpected event: %+v", events[0])
	}
}

func TestLiveSourceOnlyReadsNewBytesOnSubsequentCalls(t *testing.T) {
	dir := t.TempDir()
	refsFile := filepath.Join(dir, "waf_refs.jsonl")
	first := `{"ref":"REF1","ts":"2026-06-13T10:00:00Z","client_ip":"8.8.8.8","uri":"/a"}` + "\n"
	if err := os.WriteFile(refsFile, []byte(first), 0644); err != nil {
		t.Fatalf("write refs file: %v", err)
	}

	source := NewLiveSource(refsFile)
	events, err := source.Read(context.Background())
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one event on first read, got %d", len(events))
	}

	// Second read with no new data should yield nothing.
	events, err = source.Read(context.Background())
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no events on unchanged file, got %d", len(events))
	}

	// Append a new line and confirm only the new line is returned.
	f, err := os.OpenFile(refsFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	second := `{"ref":"REF2","ts":"2026-06-13T10:00:05Z","client_ip":"9.9.9.9","uri":"/b"}` + "\n"
	if _, err := f.WriteString(second); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	events, err = source.Read(context.Background())
	if err != nil {
		t.Fatalf("third read: %v", err)
	}
	if len(events) != 1 || events[0].Ref != "REF2" {
		t.Fatalf("expected only the newly appended event, got %+v", events)
	}
}

func TestLiveSourceHoldsBackIncompleteTrailingLine(t *testing.T) {
	dir := t.TempDir()
	refsFile := filepath.Join(dir, "waf_refs.jsonl")
	// No trailing newline: simulates a write still in flight.
	content := `{"ref":"REF1","ts":"2026-06-13T10:00:00Z","client_ip":"8.8.8.8","uri":"/a"}`
	if err := os.WriteFile(refsFile, []byte(content), 0644); err != nil {
		t.Fatalf("write refs file: %v", err)
	}

	source := NewLiveSource(refsFile)
	events, err := source.Read(context.Background())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no events for incomplete trailing line, got %d", len(events))
	}
}

func TestLiveSourceMissingFileReturnsNoEvents(t *testing.T) {
	source := NewLiveSource(filepath.Join(t.TempDir(), "missing.jsonl"))
	events, err := source.Read(context.Background())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if events != nil {
		t.Fatalf("expected nil events, got %+v", events)
	}
}
