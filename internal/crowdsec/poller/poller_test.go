package poller

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── writer tests ──────────────────────────────────────────────────────────────

func TestLogWriter_Write(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")
	w := newLogWriter(path)

	rec := DecisionRecord{
		DT:       "2026-06-08T10:00:00Z",
		Host:     "testhost",
		Platform: "CrowdSec",
		CS: decisionFields{
			EventType: "decision",
			ID:        42,
			IP:        "1.2.3.4",
			Type:      "ban",
			Scenario:  "http:scan",
			Duration:  "24h",
			Origin:    "crowdsec",
			Scope:     "Ip",
		},
	}
	if err := w.write(rec); err != nil {
		t.Fatalf("write: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed DecisionRecord
	if err := json.Unmarshal([]byte(data[:len(data)-1]), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.CS.IP != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4, got %s", parsed.CS.IP)
	}
	if parsed.CS.EventType != "decision" {
		t.Errorf("expected event_type decision, got %s", parsed.CS.EventType)
	}
}

func TestLogWriter_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "decisions.log")
	w := newLogWriter(path)
	if err := w.write(DecisionRecord{DT: "now", Host: "h", Platform: "CrowdSec"}); err != nil {
		t.Fatalf("write with missing parent: %v", err)
	}
}

// ── loadSeenIDs tests ─────────────────────────────────────────────────────────

func TestLoadSeenIDs_NonExistentFile(t *testing.T) {
	decIDs, alertIDs, err := loadSeenIDs("/nonexistent/decisions.log")
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
	if len(decIDs) != 0 || len(alertIDs) != 0 {
		t.Error("expected empty maps for missing file")
	}
}

func TestLoadSeenIDs_ReadsExistingLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")

	lines := []DecisionRecord{
		{DT: "t", Host: "h", Platform: "CrowdSec", CS: decisionFields{EventType: "decision", ID: 100, IP: "1.1.1.1"}},
		{DT: "t", Host: "h", Platform: "CrowdSec", CS: decisionFields{EventType: "alert", ID: 200, IP: "2.2.2.2"}},
		{DT: "t", Host: "h", Platform: "CrowdSec", CS: decisionFields{EventType: "decision", ID: 300, IP: "3.3.3.3"}},
	}
	w := newLogWriter(path)
	for _, l := range lines {
		if err := w.write(l); err != nil {
			t.Fatal(err)
		}
	}

	decIDs, alertIDs, err := loadSeenIDs(path)
	if err != nil {
		t.Fatalf("loadSeenIDs: %v", err)
	}
	if _, ok := decIDs[100]; !ok {
		t.Error("expected decision ID 100")
	}
	if _, ok := decIDs[300]; !ok {
		t.Error("expected decision ID 300")
	}
	if _, ok := alertIDs[200]; !ok {
		t.Error("expected alert ID 200")
	}
	if len(decIDs) != 2 {
		t.Errorf("expected 2 decision IDs, got %d", len(decIDs))
	}
}

func TestLoadSeenIDs_SkipsMalformedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")

	f, _ := os.Create(path)
	f.WriteString("not json\n")
	f.WriteString(`{"cs":{"event_type":"decision","id":999}}` + "\n")
	f.Close()

	decIDs, _, err := loadSeenIDs(path)
	if err != nil {
		t.Fatalf("loadSeenIDs: %v", err)
	}
	if _, ok := decIDs[999]; !ok {
		t.Error("expected ID 999 to be loaded")
	}
}

// ── deduplication test ────────────────────────────────────────────────────────

func TestPoller_Deduplication(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]LAPIDecision{
			{ID: 1, Value: "10.0.0.1", Type: "ban", Scenario: "http:scan", Duration: "1h", Origin: "crowdsec", Scope: "Ip"},
		})
	}))
	defer ts.Close()

	dir := t.TempDir()
	cfg := Config{
		Enabled:  true,
		LAPIURL:  ts.URL,
		LAPIKey:  "test-key",
		Interval: time.Hour,
		LogPath:  filepath.Join(dir, "decisions.log"),
		CscliBin: "false", // no-op binary — alerts will fail, decisions path is what we test
		Timeout:  5 * time.Second,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	p := New(cfg, logger)

	// First poll: should write 1 record.
	nd, _, _ := p.poll(context.Background())
	if nd != 1 {
		t.Fatalf("first poll: expected 1 decision written, got %d", nd)
	}

	// Second poll: same ID should be deduped.
	nd2, _, _ := p.poll(context.Background())
	if nd2 != 0 {
		t.Fatalf("second poll: expected 0 (duplicate), got %d", nd2)
	}
}

// ── LAPI error handling ───────────────────────────────────────────────────────

func TestPoller_LAPIUnavailable(t *testing.T) {
	cfg := Config{
		Enabled:  true,
		LAPIURL:  "http://127.0.0.1:19999", // nothing listening
		LAPIKey:  "key",
		Interval: time.Hour,
		LogPath:  filepath.Join(t.TempDir(), "decisions.log"),
		CscliBin: "false",
		Timeout:  500 * time.Millisecond,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	p := New(cfg, logger)

	_, _, err := p.poll(context.Background())
	if err == nil {
		t.Fatal("expected error when LAPI is unavailable")
	}
}

// ── restart preload test ──────────────────────────────────────────────────────

func TestPoller_PreloadPreventsFlood(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")

	// Pre-populate log with existing decisions.
	w := newLogWriter(path)
	for _, id := range []int64{1, 2, 3} {
		w.write(DecisionRecord{
			DT: "t", Host: "h", Platform: "CrowdSec",
			CS: decisionFields{EventType: "decision", ID: id, IP: "1.2.3.4"},
		})
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return the same 3 decisions that are already in the log.
		json.NewEncoder(w).Encode([]LAPIDecision{
			{ID: 1, Value: "1.0.0.1"},
			{ID: 2, Value: "1.0.0.2"},
			{ID: 3, Value: "1.0.0.3"},
		})
	}))
	defer ts.Close()

	cfg := Config{
		Enabled:  true,
		LAPIURL:  ts.URL,
		LAPIKey:  "k",
		Interval: time.Hour,
		LogPath:  path,
		CscliBin: "false",
		Timeout:  5 * time.Second,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	p := New(cfg, logger)

	if err := p.preload(context.Background()); err != nil {
		t.Fatalf("preload: %v", err)
	}

	nd, _, _ := p.poll(context.Background())
	if nd != 0 {
		t.Errorf("after preload, expected 0 new decisions (all already seen), got %d", nd)
	}
}

// ── record format test ────────────────────────────────────────────────────────

func TestDecisionRecord_Format(t *testing.T) {
	rec := DecisionRecord{
		DT:       "2026-06-08T10:00:00Z",
		Host:     "NUC8i3BEH",
		Platform: "CrowdSec",
		CS: decisionFields{
			EventType: "decision",
			ID:        13260738,
			IP:        "162.216.149.138",
			Type:      "ban",
			Scenario:  "http:exploit",
			Duration:  "59m57s",
			Origin:    "CAPI",
			Scope:     "Ip",
			Simulated: false,
		},
	}

	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Verify top-level keys match the Python format.
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"dt", "host", "platform", "cs"} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing top-level key %q in JSON output", key)
		}
	}
	cs, ok := m["cs"].(map[string]any)
	if !ok {
		t.Fatal("cs field is not an object")
	}
	for _, key := range []string{"event_type", "id", "ip", "type", "scenario", "duration", "origin", "scope"} {
		if _, ok := cs[key]; !ok {
			t.Errorf("missing cs.%q in JSON output", key)
		}
	}
}
