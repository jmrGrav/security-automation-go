package sqlite

import (
	"context"
	"testing"
	"time"

	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

func TestReportingEvidenceStorePersistsAndLists(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewReportingEvidenceStore(db)
	first := reporting.DecisionEvidence{
		EvidenceID:        "ev-1",
		Timestamp:         time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC),
		Source:            "cloudflare_waf",
		IP:                "8.8.8.8",
		AbuseType:         "exploit_attempt",
		Decision:          "reported",
		Reported:          true,
		AbuseIPDBReported: true,
	}
	second := reporting.DecisionEvidence{
		EvidenceID:        "ev-2",
		Timestamp:         time.Date(2026, 5, 27, 11, 0, 0, 0, time.UTC),
		Source:            "crowdsec_waf",
		IP:                "8.8.8.8",
		Decision:          "suppressed",
		Suppressed:        true,
		SuppressionReason: "abuseipdb_recently_reported",
	}
	if err := store.Append(context.Background(), first); err != nil {
		t.Fatalf("append first: %v", err)
	}
	if err := store.Append(context.Background(), second); err != nil {
		t.Fatalf("append second: %v", err)
	}

	got, err := store.List(context.Background(), 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected two evidence entries, got %d", len(got))
	}
	if got[0].EvidenceID != "ev-2" || got[1].EvidenceID != "ev-1" {
		t.Fatalf("unexpected order: %+v", got)
	}

	found, ok, err := store.Get(context.Background(), "ev-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !ok || found.EvidenceID != "ev-1" {
		t.Fatalf("unexpected get result: ok=%v evidence=%+v", ok, found)
	}

	search, err := store.Search(context.Background(), reporting.EvidenceSearchOptions{
		IP:       "8.8.8.8",
		Source:   "crowdsec_waf",
		Decision: "suppressed",
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(search) != 1 || search[0].EvidenceID != "ev-2" {
		t.Fatalf("unexpected search result: %+v", search)
	}
}

func TestReportReservationStorePreventsConcurrentPendingForSameIP(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewReportReservationStore(db)
	ctx := context.Background()
	first := reporting.ReportReservation{
		IP:             "8.8.4.4",
		Source:         "cloudflare_waf",
		IdempotencyKey: "idem-1",
		EvidenceID:     "ev-pending-1",
		Status:         reporting.ReportStatusPending,
		ExpiresAt:      time.Now().UTC().Add(time.Hour),
	}
	if err := store.Reserve(ctx, first); err != nil {
		t.Fatalf("reserve first: %v", err)
	}
	second := first
	second.IdempotencyKey = "idem-2"
	second.EvidenceID = "ev-pending-2"
	if err := store.Reserve(ctx, second); err == nil {
		t.Fatal("expected duplicate pending reservation to fail")
	}
	if err := store.MarkStatus(ctx, first.EvidenceID, reporting.ReportStatusReported); err != nil {
		t.Fatalf("mark reported: %v", err)
	}
	if err := store.Reserve(ctx, second); err != nil {
		t.Fatalf("reserve after reported status: %v", err)
	}
}

func TestReportReservationStoreAllowsSameIdempotencyAndExpiresOldPending(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewReportReservationStore(db)
	ctx := context.Background()
	expired := reporting.ReportReservation{
		IP:             "8.8.4.5",
		Source:         "cloudflare_waf",
		IdempotencyKey: "idem-1",
		EvidenceID:     "ev-pending-1",
		Status:         reporting.ReportStatusPending,
		ExpiresAt:      time.Now().UTC().Add(-time.Minute),
	}
	if err := store.Reserve(ctx, expired); err != nil {
		t.Fatalf("reserve expired pending: %v", err)
	}
	same := expired
	if err := store.Reserve(ctx, same); err != nil {
		t.Fatalf("same idempotency reservation should be idempotent: %v", err)
	}
	next := reporting.ReportReservation{
		IP:             expired.IP,
		Source:         "openresty_waf",
		IdempotencyKey: "idem-2",
		EvidenceID:     "ev-pending-2",
		Status:         reporting.ReportStatusPending,
		ExpiresAt:      time.Now().UTC().Add(time.Hour),
	}
	if err := store.Reserve(ctx, next); err != nil {
		t.Fatalf("expired pending should not permanently block new reservation: %v", err)
	}
}

func TestReportReservationStoreListsRetryableWithReportPayload(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewReportReservationStore(db)
	ctx := context.Background()
	reservation := reporting.ReportReservation{
		IP:             "8.8.4.6",
		Source:         "crowdsec_waf",
		IdempotencyKey: "idem-retry",
		EvidenceID:     "ev-retry",
		Status:         reporting.ReportStatusPending,
		ExpiresAt:      time.Now().UTC().Add(time.Hour),
		Report: abmodels.ExecutableReport{
			ExecutionID: "idem-retry",
			IP:          "8.8.4.6",
			Categories:  "21",
			Comment:     "CrowdSec WAF: 1 hits in 300s | action=block | abuse=exploit_attempt | categories=Web App Attack | rule_id=r1 | URIs=/x",
		},
	}
	if err := store.Reserve(ctx, reservation); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	items, err := store.ListRetryable(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatalf("list retryable: %v", err)
	}
	if len(items) != 1 || items[0].Reservation.Report.Comment != reservation.Report.Comment {
		t.Fatalf("expected retryable report payload, got %+v", items)
	}
	if err := store.RecordAttempt(ctx, reservation.EvidenceID, reporting.ReportStatusFailed, "rate limited", time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatalf("record attempt: %v", err)
	}
	items, err = store.ListRetryable(ctx, time.Now().UTC().Add(2*time.Minute), 10)
	if err != nil {
		t.Fatalf("list retryable after backoff: %v", err)
	}
	if len(items) != 1 || items[0].AttemptCount != 1 || items[0].LastError != "rate limited" {
		t.Fatalf("expected retry attempt metadata, got %+v", items)
	}
}
