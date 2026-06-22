package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"testing"
	"time"

	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	"github.com/jm/security-automation-go/internal/adapters/nginxerrors"
	"github.com/jm/security-automation-go/internal/adapters/wafref"
	cfmodels "github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

// TestNewDaemonContextSignalGoroutineExitsOnManualCancel guards against the
// goroutine leak described in GitHub issue #65: newDaemonContext started a
// goroutine that blocked forever on <-sigChan, never observing the returned
// context. A normal shutdown (parent cancels the context rather than
// sending a signal) left that goroutine — and its signal.Notify
// registration — running for the lifetime of the process. The goroutine
// must now also select on ctx.Done() and exit promptly on manual cancel,
// without ever receiving a signal.
func TestNewDaemonContextSignalGoroutineExitsOnManualCancel(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// os/signal.Notify's first call in a process starts an internal runtime
	// housekeeping goroutine that persists for the program's lifetime — warm
	// that up before taking the baseline so it isn't mistaken for the leak
	// under test.
	warmup := make(chan os.Signal, 1)
	signal.Notify(warmup, syscall.SIGUSR1)
	signal.Stop(warmup)

	before := runtime.NumGoroutine()

	_, cancel := newDaemonContext(context.Background(), logger, nil)
	cancel()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("signal-handling goroutine still running after manual cancel (before=%d, after=%d)",
		before, runtime.NumGoroutine())
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

type fakeCursorStore struct {
	loadValue time.Time
	found     bool
	loadErr   error
	saved     []time.Time
	saveErr   error
}

func (f *fakeCursorStore) Load(context.Context, string) (time.Time, bool, error) {
	return f.loadValue, f.found, f.loadErr
}

func (f *fakeCursorStore) Save(_ context.Context, _ string, value time.Time) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved = append(f.saved, value)
	return nil
}

func TestReplayQuerySinceAppliesOverlap(t *testing.T) {
	base := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	got := replayQuerySince(base, 10*time.Minute)
	want := base.Add(-10 * time.Minute)
	if !got.Equal(want) {
		t.Fatalf("unexpected overlap query since: got=%s want=%s", got, want)
	}
}

func TestNextWAFReplayCursorUsesHighWatermark(t *testing.T) {
	previous := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	hw := previous.Add(2 * time.Minute)
	got := nextWAFReplayCursor(cloudflareevent.ProcessingReport{HighWatermark: hw}, previous, previous.Add(30*time.Second))
	if !got.Equal(hw) {
		t.Fatalf("expected high watermark cursor, got=%s want=%s", got, hw)
	}
}

func TestLoadWAFReplayCursorFallsBackOnCorruption(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(testWriter{t: t}, nil))
	store := &fakeCursorStore{loadErr: errors.New("bad cursor")}
	got := loadWAFReplayCursor(context.Background(), logger, store, time.Hour)
	if got.IsZero() {
		t.Fatal("expected fallback cursor to be non-zero")
	}
}

type fakeWAFSource struct {
	events []cfmodels.WAFEvent
	err    error
}

func (f fakeWAFSource) ListWAFEventsSince(context.Context, string, time.Time) ([]cfmodels.WAFEvent, error) {
	return f.events, f.err
}

type fakeAbuseReporter struct {
	err   error
	calls int
}

func (f *fakeAbuseReporter) Execute(_ context.Context, _ []abmodels.ExecutableReport) error {
	f.calls++
	return f.err
}

func TestRunWAFReplayIterationDoesNotAdvanceCursorOnProcessingError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(testWriter{t: t}, nil))
	store := &fakeCursorStore{}
	reportingService := reporting.New(&fakeAbuseReporter{err: http.ErrHandlerTimeout}, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	service := cloudflareevent.NewService(fakeWAFSource{
		events: []cfmodels.WAFEvent{{
			Action:             "block",
			ClientIP:           "8.8.8.8",
			Datetime:           time.Date(2026, 5, 28, 10, 5, 0, 0, time.UTC),
			ClientRequestPath:  "/search",
			ClientRequestQuery: "q=union+select+1",
			Host:               "arleo.eu",
			Source:             "waf",
			UserAgent:          "sqlmap/1.0",
			RuleID:             "cf-rule-1",
			Description:        "SQLi rule",
		}},
	}, reportingService)

	since := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	got := runWAFReplayIteration(context.Background(), logger, "zone", service, store, since, since.Add(time.Minute), nil, nil)
	if !got.Equal(since) {
		t.Fatalf("expected cursor to stay put on processing error, got=%s want=%s", got, since)
	}
	if len(store.saved) != 0 {
		t.Fatalf("expected no cursor save on error, got %d saves", len(store.saved))
	}
}

func TestRunWAFReplayIterationAdvancesCursorOnSuccess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(testWriter{t: t}, nil))
	store := &fakeCursorStore{}
	reportingService := reporting.New(&fakeAbuseReporter{}, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	hw := time.Date(2026, 5, 28, 10, 7, 0, 0, time.UTC)
	service := cloudflareevent.NewService(fakeWAFSource{
		events: []cfmodels.WAFEvent{{
			Action:             "block",
			ClientIP:           "8.8.8.8",
			Datetime:           hw,
			ClientRequestPath:  "/search",
			ClientRequestQuery: "q=union+select+1",
			Host:               "arleo.eu",
			Source:             "waf",
			UserAgent:          "sqlmap/1.0",
			RuleID:             "cf-rule-1",
			Description:        "SQLi rule",
		}},
	}, reportingService)

	since := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	got := runWAFReplayIteration(context.Background(), logger, "zone", service, store, since, since.Add(time.Minute), nil, nil)
	if !got.Equal(hw) {
		t.Fatalf("expected cursor to advance to high watermark, got=%s want=%s", got, hw)
	}
	if len(store.saved) != 1 || !store.saved[0].Equal(hw) {
		t.Fatalf("unexpected saved cursors: %+v", store.saved)
	}
}

func TestRunWAFReplayIterationDoesNotAdvanceCursorOnSaveFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(testWriter{t: t}, nil))
	store := &fakeCursorStore{saveErr: errors.New("disk full")}
	reportingService := reporting.New(&fakeAbuseReporter{}, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	hw := time.Date(2026, 5, 28, 10, 7, 0, 0, time.UTC)
	service := cloudflareevent.NewService(fakeWAFSource{
		events: []cfmodels.WAFEvent{{
			Action:             "block",
			ClientIP:           "8.8.8.8",
			Datetime:           hw,
			ClientRequestPath:  "/search",
			ClientRequestQuery: "q=union+select+1",
			Host:               "arleo.eu",
			Source:             "waf",
			UserAgent:          "sqlmap/1.0",
			RuleID:             "cf-rule-1",
			Description:        "SQLi rule",
		}},
	}, reportingService)

	since := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	got := runWAFReplayIteration(context.Background(), logger, "zone", service, store, since, since.Add(time.Minute), nil, nil)
	if !got.Equal(since) {
		t.Fatalf("expected cursor to stay put on save failure, got=%s want=%s", got, since)
	}
}

func TestNewAuthenticator(t *testing.T) {
	t.Run("with_env_token", func(t *testing.T) {
		t.Setenv("CF_SYNC_API_TOKEN", "test-token")
		t.Setenv("CF_SYNC_API_TOKEN_FILE", "")
		a, err := newAuthenticator()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		id, err := a.Authenticate("test-token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id.OperatorID != "admin" {
			t.Errorf("expected operator ID 'admin', got %q", id.OperatorID)
		}
	})

	t.Run("with_file_token", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "token*")
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString("file-secret\n")
		f.Close()
		t.Setenv("CF_SYNC_API_TOKEN_FILE", f.Name())
		t.Setenv("CF_SYNC_API_TOKEN", "env-token-ignored")

		a, err := newAuthenticator()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		id, err := a.Authenticate("file-secret")
		if err != nil {
			t.Fatalf("file token not accepted: %v", err)
		}
		if id.OperatorID != "admin" {
			t.Errorf("expected operator ID 'admin', got %q", id.OperatorID)
		}
		_, envErr := a.Authenticate("env-token-ignored")
		if envErr == nil {
			t.Error("env token should be rejected when file token is set")
		}
	})

	t.Run("file_missing_fails_startup", func(t *testing.T) {
		t.Setenv("CF_SYNC_API_TOKEN_FILE", "/nonexistent/path/token")
		t.Setenv("CF_SYNC_API_TOKEN", "fallback")
		_, err := newAuthenticator()
		if err == nil {
			t.Fatal("expected error for missing token file, got nil")
		}
	})

	t.Run("empty_token_fails", func(t *testing.T) {
		t.Setenv("CF_SYNC_API_TOKEN", "")
		t.Setenv("CF_SYNC_API_TOKEN_FILE", "")
		_, err := newAuthenticator()
		if err == nil {
			t.Fatal("expected error for missing CF_SYNC_API_TOKEN, got nil")
		}
	})
}

// TestWAFRefOffsetSurvivesSimulatedRestart guards against re-reading the
// entire waf_refs.jsonl file (and re-recording its refs into evidence) on
// every daemon restart. processWAFRefOnce must persist its byte offset via
// the cursor store, and a freshly constructed LiveSource/wafBundle — as
// happens on restart — must pick that offset back up via loadWAFRefOffset.
func TestWAFRefOffsetSurvivesSimulatedRestart(t *testing.T) {
	dir := t.TempDir()
	refsFile := dir + "/waf_refs.jsonl"
	line := `{"ref":"REF1","ts":"2026-06-13T10:00:00Z","client_ip":"8.8.8.8","host":"arleo.eu","method":"GET","uri":"/a","reason":"appsec"}` + "\n"
	if err := os.WriteFile(refsFile, []byte(line), 0644); err != nil {
		t.Fatalf("write refs file: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(testWriter{t}, nil))
	store := &fakeCursorStore{}
	svc := reporting.New(&fakeAbuseReporter{}, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)

	// First run: a fresh LiveSource reads the one existing line.
	bundle1 := &wafBundle{wrSource: wafref.NewLiveSource(refsFile), wr: wafref.NewService(svc)}
	loadWAFRefOffset(context.Background(), logger, store, bundle1)
	processWAFRefOnce(context.Background(), logger, bundle1, store)
	if len(store.saved) != 1 {
		t.Fatalf("expected offset to be persisted after first run, got %d saves", len(store.saved))
	}
	store.loadValue = store.saved[len(store.saved)-1]
	store.found = true

	// Simulated restart: a brand new LiveSource/bundle over the same file.
	// Without restoring the persisted offset, this would re-read REF1 from
	// byte 0 and re-process it, producing a duplicate evidence row.
	bundle2 := &wafBundle{wrSource: wafref.NewLiveSource(refsFile), wr: wafref.NewService(svc)}
	loadWAFRefOffset(context.Background(), logger, store, bundle2)
	if got := bundle2.wrSource.Offset(); got != int64(len(line)) {
		t.Fatalf("expected restored offset %d, got %d", len(line), got)
	}

	savesBefore := len(store.saved)
	processWAFRefOnce(context.Background(), logger, bundle2, store)
	if len(store.saved) != savesBefore {
		t.Fatalf("expected no new events/saves on restart with no new data, got %d saves", len(store.saved))
	}

	// New ref appended after the restart must still be picked up.
	more := `{"ref":"REF2","ts":"2026-06-13T10:05:00Z","client_ip":"9.9.9.9","host":"arleo.eu","method":"GET","uri":"/b","reason":"appsec"}` + "\n"
	f, err := os.OpenFile(refsFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	if _, err := f.WriteString(more); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	processWAFRefOnce(context.Background(), logger, bundle2, store)
	if len(store.saved) != savesBefore+1 {
		t.Fatalf("expected offset to advance after new ref appended, got %d saves", len(store.saved))
	}
}

// TestNginxErrorsCursorAdvancesWithoutOverlapAndAvoidsDuplicates guards
// against the failure mode the Cloudflare WAF replay's overlap window has:
// since reporting's decisionEvidenceID is wall-clock-seeded (not idempotent
// per logical event), re-reading an overlap window on every tick would
// re-record the same burst as a brand new evidence row each time. The
// nginxerrors cursor must advance straight to the high watermark with no
// overlap, so a burst already seen is never reprocessed on the next tick.
func TestNginxErrorsCursorAdvancesWithoutOverlapAndAvoidsDuplicates(t *testing.T) {
	dir := t.TempDir()
	line := func(ip, ts, uri string) string {
		return ip + ` - - [` + ts + `] "GET ` + uri + ` HTTP/1.1" 404 123 "-" "scanner/1.0"`
	}
	content := line("9.9.9.9", "13/Jun/2026:10:00:00 +0000", "/admin") + "\n" +
		line("9.9.9.9", "13/Jun/2026:10:00:01 +0000", "/admin") + "\n" +
		line("9.9.9.9", "13/Jun/2026:10:00:02 +0000", "/admin") + "\n"
	if err := os.WriteFile(dir+"/access.log", []byte(content), 0644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(testWriter{t}, nil))
	store := &fakeCursorStore{}
	svc := reporting.New(&fakeAbuseReporter{}, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	erSource := nginxerrors.NewLiveSource(dir)
	bundle := &wafBundle{erSource: erSource, er: nginxerrors.NewService(erSource, svc)}

	since := time.Date(2026, 6, 13, 9, 0, 0, 0, time.UTC)
	since = processNginxErrorsOnce(context.Background(), logger, bundle, store, since)
	if len(store.saved) != 1 {
		t.Fatalf("expected cursor to be persisted after the qualifying burst, got %d saves", len(store.saved))
	}
	wantWatermark := time.Date(2026, 6, 13, 10, 0, 2, 0, time.UTC)
	if !since.Equal(wantWatermark) {
		t.Fatalf("expected cursor to advance to the burst's last event time %s, got %s", wantWatermark, since)
	}

	// Re-running against the same unchanged file must not reprocess the
	// burst (no overlap re-read, no duplicate evidence/save).
	savesBefore := len(store.saved)
	since2 := processNginxErrorsOnce(context.Background(), logger, bundle, store, since)
	if len(store.saved) != savesBefore {
		t.Fatalf("expected no new save when no new entries exist past the cursor, got %d saves", len(store.saved))
	}
	if !since2.Equal(since) {
		t.Fatalf("expected cursor to stay put with no new data, got %s want %s", since2, since)
	}
}
