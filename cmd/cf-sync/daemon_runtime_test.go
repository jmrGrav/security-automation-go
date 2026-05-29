package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"time"

	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	cfmodels "github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

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
	got := runWAFReplayIteration(context.Background(), logger, "zone", service, store, since, since.Add(time.Minute))
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
	got := runWAFReplayIteration(context.Background(), logger, "zone", service, store, since, since.Add(time.Minute))
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
	got := runWAFReplayIteration(context.Background(), logger, "zone", service, store, since, since.Add(time.Minute))
	if !got.Equal(since) {
		t.Fatalf("expected cursor to stay put on save failure, got=%s want=%s", got, since)
	}
}
