package reporting_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

type fakeLeaseGuard struct {
	err   error
	calls int
}

func (g *fakeLeaseGuard) ValidateOutboxItem(context.Context, reporting.ReportOutboxItem) error {
	g.calls++
	return g.err
}

func TestOutboxWorkerRetriesPendingReservation(t *testing.T) {
	base := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	reporter := &fakeReporter{}
	dedup := newFakeDedupStore()
	evidence := &fakeEvidenceStore{}
	store := &fakeReservationStore{items: []reporting.ReportOutboxItem{{
		Reservation: reporting.ReportReservation{
			IP:             "8.8.8.8",
			Source:         "cloudflare_waf",
			IdempotencyKey: "exec-1",
			EvidenceID:     "ev-1",
			Status:         reporting.ReportStatusPending,
			Report: abmodels.ExecutableReport{
				ExecutionID: "exec-1",
				IP:          "8.8.8.8",
				Categories:  "21",
				Comment:     "Cloudflare WAF: 1 hits in 300s | action=block | abuse=exploit_attempt | categories=Web App Attack | rule_id=r1 | URIs=/x",
				CreatedAt:   base,
			},
		},
	}}}
	worker := reporting.NewOutboxWorker(store, reporter, dedup, evidence, &sinks.RecorderSink{}, reporting.OutboxWorkerConfig{Clock: func() time.Time { return base }})

	processed, err := worker.ProcessOnce(context.Background())
	if err != nil {
		t.Fatalf("process once: %v", err)
	}
	if processed != 1 || len(reporter.Reports()) != 1 {
		t.Fatalf("expected one retry report, processed=%d reports=%d", processed, len(reporter.Reports()))
	}
	if store.statuses["ev-1"] != reporting.ReportStatusReported {
		t.Fatalf("expected reported status, got %#v", store.statuses)
	}
	if dedup.markCount != 1 || len(evidence.Evidence()) == 0 {
		t.Fatalf("expected dedup mark and evidence, marks=%d evidence=%d", dedup.markCount, len(evidence.Evidence()))
	}
}

func TestOutboxWorkerFailureRecordsRetryStateWithoutMarkingDedup(t *testing.T) {
	base := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	reporter := &fakeReporter{err: errors.New("abuseipdb 429")}
	dedup := newFakeDedupStore()
	store := &fakeReservationStore{items: []reporting.ReportOutboxItem{{
		Reservation: reporting.ReportReservation{
			IP:             "8.8.4.4",
			Source:         "openresty_waf",
			IdempotencyKey: "exec-2",
			EvidenceID:     "ev-2",
			Status:         reporting.ReportStatusPending,
			Report:         abmodels.ExecutableReport{ExecutionID: "exec-2", IP: "8.8.4.4", Categories: "21", Comment: "OpenResty WAF: 1 hits in 300s | action=block | abuse=exploit_attempt | categories=Web App Attack | rule_id=r1 | URIs=/x", CreatedAt: base},
		},
	}}}
	worker := reporting.NewOutboxWorker(store, reporter, dedup, nil, nil, reporting.OutboxWorkerConfig{Clock: func() time.Time { return base }, RetryBackoff: time.Minute})

	processed, err := worker.ProcessOnce(context.Background())
	if err == nil {
		t.Fatal("expected retry error")
	}
	if processed != 1 {
		t.Fatalf("expected processed item, got %d", processed)
	}
	if store.statuses["ev-2"] != reporting.ReportStatusFailed {
		t.Fatalf("expected failed status, got %#v", store.statuses)
	}
	if dedup.markCount != 0 {
		t.Fatalf("failed upstream report must not mark dedup, got %d", dedup.markCount)
	}
}

func TestOutboxWorkerRunStopsOnContextCancel(t *testing.T) {
	base := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	store := &fakeReservationStore{}
	worker := reporting.NewOutboxWorker(
		store,
		&fakeReporter{},
		newFakeDedupStore(),
		nil,
		nil,
		reporting.OutboxWorkerConfig{
			Clock:        func() time.Time { return base },
			Interval:     5 * time.Millisecond,
			RetryBackoff: time.Minute,
		},
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	time.Sleep(15 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop on context cancel")
	}
}

func TestOutboxWorkerLeaseGuardRefusalSkipsUpstreamCall(t *testing.T) {
	base := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	reporter := &fakeReporter{}
	guard := &fakeLeaseGuard{err: errors.New("lost lease")}
	store := &fakeReservationStore{items: []reporting.ReportOutboxItem{{
		Reservation: reporting.ReportReservation{
			IP:             "8.8.8.8",
			Source:         "cloudflare_waf",
			IdempotencyKey: "exec-guard",
			EvidenceID:     "ev-guard",
			Status:         reporting.ReportStatusPending,
			Report:         abmodels.ExecutableReport{ExecutionID: "exec-guard", IP: "8.8.8.8", Categories: "21", Comment: "x", CreatedAt: base},
		},
	}}}
	worker := reporting.NewOutboxWorker(
		store,
		reporter,
		newFakeDedupStore(),
		&fakeEvidenceStore{},
		&sinks.RecorderSink{},
		reporting.OutboxWorkerConfig{
			Clock:      func() time.Time { return base },
			LeaseGuard: guard,
		},
	)

	processed, err := worker.ProcessOnce(context.Background())
	if err == nil {
		t.Fatal("expected lease guard refusal")
	}
	if processed != 0 {
		t.Fatalf("expected zero processed items after lease guard refusal, got %d", processed)
	}
	if len(reporter.Reports()) != 0 {
		t.Fatalf("expected no upstream report call when lease guard refuses, got %d", len(reporter.Reports()))
	}
	if guard.calls != 1 {
		t.Fatalf("expected one lease guard validation call, got %d", guard.calls)
	}
}

func TestOutboxWorkerClaimsRowBeforeReporting(t *testing.T) {
	db, err := sqlite.New(t.TempDir())
	if err != nil {
		t.Fatalf("sqlite new: %v", err)
	}
	defer db.Close()

	store := sqlite.NewReportReservationStore(db)
	base := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	reservation := reporting.ReportReservation{
		IP:             "8.8.8.8",
		Source:         "cloudflare_waf",
		IdempotencyKey: "exec-claim",
		EvidenceID:     "ev-claim",
		Status:         reporting.ReportStatusPending,
		ExpiresAt:      base.Add(time.Hour),
		Report:         abmodels.ExecutableReport{ExecutionID: "exec-claim", IP: "8.8.8.8", Categories: "21", Comment: "x", CreatedAt: base},
	}
	if err := store.Reserve(context.Background(), reservation); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	reporter := &blockingReporter{
		started: started,
		release: release,
	}
	worker := reporting.NewOutboxWorker(store, reporter, newFakeDedupStore(), nil, nil, reporting.OutboxWorkerConfig{
		Clock:      func() time.Time { return base },
		ClaimLease: time.Second,
	})

	errs := make(chan error, 2)
	go func() {
		_, err := worker.ProcessOnce(context.Background())
		errs <- err
	}()
	<-started
	go func() {
		_, err := worker.ProcessOnce(context.Background())
		errs <- err
	}()
	close(release)

	if err := <-errs; err != nil {
		t.Fatalf("first worker: %v", err)
	}
	if err := <-errs; err != nil {
		t.Fatalf("second worker: %v", err)
	}
	if got := len(reporter.Reports()); got != 1 {
		t.Fatalf("expected exactly one upstream report, got %d", got)
	}
}

type blockingReporter struct {
	started chan struct{}
	release chan struct{}
	mu      sync.Mutex
	reports []abmodels.ExecutableReport
}

func (b *blockingReporter) Execute(_ context.Context, reports []abmodels.ExecutableReport) error {
	b.mu.Lock()
	b.reports = append(b.reports, reports...)
	b.mu.Unlock()
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-b.release
	return nil
}

func (b *blockingReporter) Reports() []abmodels.ExecutableReport {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]abmodels.ExecutableReport(nil), b.reports...)
}
