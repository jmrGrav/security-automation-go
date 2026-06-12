package sqlite

import (
	"context"
	"fmt"
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

func TestReportingEvidenceStorePrunesOldEntries(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewReportingEvidenceStore(db)
	base := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	store.retention = 24 * time.Hour
	store.maxEntries = 2
	store.cleanupEvery = 1
	store.now = func() time.Time { return base }

	for i := 1; i <= 3; i++ {
		ev := reporting.DecisionEvidence{
			EvidenceID: fmt.Sprintf("ev-%d", i),
			Timestamp:  base.Add(time.Duration(i) * time.Minute),
			Source:     "cloudflare_waf",
			IP:         "8.8.8.8",
			Decision:   "reported",
		}
		if err := store.Append(context.Background(), ev); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	got, err := store.List(context.Background(), 10)
	if err != nil {
		t.Fatalf("list after prune: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected pruned evidence to stay bounded at 2, got %d", len(got))
	}
	if got[0].EvidenceID != "ev-3" || got[1].EvidenceID != "ev-2" {
		t.Fatalf("unexpected evidence retention order: %+v", got)
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

func TestReportReservationStorePrunesOldRows(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewReportReservationStore(db)
	store.retention = 24 * time.Hour
	store.maxEntries = 2
	store.cleanupEvery = 1
	base := time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }

	for i := 1; i <= 3; i++ {
		reservation := reporting.ReportReservation{
			IP:             fmt.Sprintf("8.8.4.%d", i),
			Source:         "cloudflare_waf",
			IdempotencyKey: fmt.Sprintf("idem-%d", i),
			EvidenceID:     fmt.Sprintf("ev-%d", i),
			Status:         reporting.ReportStatusPending,
			ExpiresAt:      base.Add(time.Hour),
		}
		if err := store.Reserve(context.Background(), reservation); err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
	}

	items, err := store.ListRetryable(context.Background(), base, 10)
	if err != nil {
		t.Fatalf("list retryable after prune: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected outbox to stay bounded at 2 rows, got %d", len(items))
	}
	if items[0].Reservation.EvidenceID != "ev-2" || items[1].Reservation.EvidenceID != "ev-3" {
		t.Fatalf("unexpected outbox retention order: %+v", items)
	}
}

func TestReportReservationStoreClaimRetryableLeasesRowsUntilClaimExpires(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewReportReservationStore(db)
	ctx := context.Background()
	now := time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC)
	reservation := reporting.ReportReservation{
		IP:             "8.8.4.7",
		Source:         "cloudflare_waf",
		IdempotencyKey: "idem-claim",
		EvidenceID:     "ev-claim",
		Status:         reporting.ReportStatusPending,
		ExpiresAt:      now.Add(time.Hour),
		Report: abmodels.ExecutableReport{
			ExecutionID: "idem-claim",
			IP:          "8.8.4.7",
			Categories:  "21",
			Comment:     "Cloudflare WAF: retry claim",
			CreatedAt:   now,
		},
	}
	if err := store.Reserve(ctx, reservation); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	claimUntil := now.Add(time.Minute)
	first, err := store.ClaimRetryable(ctx, now, 10, claimUntil)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if len(first) != 1 || first[0].Reservation.EvidenceID != reservation.EvidenceID {
		t.Fatalf("expected first claim to return reservation, got %+v", first)
	}

	second, err := store.ClaimRetryable(ctx, now.Add(30*time.Second), 10, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("second claim before lease expiry: %v", err)
	}
	if len(second) != 0 {
		t.Fatalf("expected active claim lease to hide row, got %+v", second)
	}

	third, err := store.ClaimRetryable(ctx, claimUntil.Add(time.Nanosecond), 10, claimUntil.Add(time.Minute))
	if err != nil {
		t.Fatalf("third claim after lease expiry: %v", err)
	}
	if len(third) != 1 || third[0].Reservation.EvidenceID != reservation.EvidenceID {
		t.Fatalf("expected row to be retryable after claim lease expiry, got %+v", third)
	}
}

func TestReportingEvidenceStore_Count(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	store := NewReportingEvidenceStore(db)

	evs := []reporting.DecisionEvidence{
		{EvidenceID: "ev-1", Source: "cloudflare_waf", IP: "1.1.1.1", AbuseIPDBReported: true, Decision: "report", Timestamp: time.Now()},
		{EvidenceID: "ev-2", Source: "cloudflare_waf", IP: "2.2.2.2", AbuseIPDBReported: false, Suppressed: true, Decision: "suppressed", Timestamp: time.Now()},
		{EvidenceID: "ev-3", Source: "crowdsec_waf", IP: "3.3.3.3", AbuseIPDBReported: false, Decision: "report_pending", Timestamp: time.Now()},
	}
	for _, ev := range evs {
		if err := store.Append(ctx, ev); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	total, err := store.Count(ctx, reporting.EvidenceSearchOptions{})
	if err != nil {
		t.Fatalf("count all: %v", err)
	}
	if total != 3 {
		t.Errorf("count all: want 3, got %d", total)
	}

	reported, err := store.Count(ctx, reporting.EvidenceSearchOptions{AbuseIPDBReported: true})
	if err != nil {
		t.Fatalf("count reported: %v", err)
	}
	if reported != 1 {
		t.Errorf("count reported: want 1, got %d", reported)
	}

	suppressed, err := store.Count(ctx, reporting.EvidenceSearchOptions{Suppressed: true})
	if err != nil {
		t.Fatalf("count suppressed: %v", err)
	}
	if suppressed != 1 {
		t.Errorf("count suppressed: want 1, got %d", suppressed)
	}

	bySrc, err := store.Count(ctx, reporting.EvidenceSearchOptions{Source: "crowdsec_waf"})
	if err != nil {
		t.Fatalf("count by source: %v", err)
	}
	if bySrc != 1 {
		t.Errorf("count by source: want 1, got %d", bySrc)
	}
}

func TestReportingEvidenceStore_SearchAbuseIPDBReportedFilter(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	store := NewReportingEvidenceStore(db)

	if err := store.Append(ctx, reporting.DecisionEvidence{EvidenceID: "r1", IP: "1.1.1.1", AbuseIPDBReported: true, Timestamp: time.Now()}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := store.Append(ctx, reporting.DecisionEvidence{EvidenceID: "r2", IP: "2.2.2.2", AbuseIPDBReported: false, Timestamp: time.Now()}); err != nil {
		t.Fatalf("append: %v", err)
	}

	results, err := store.Search(ctx, reporting.EvidenceSearchOptions{AbuseIPDBReported: true})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) != 1 || results[0].EvidenceID != "r1" {
		t.Errorf("expected only reported ev, got %+v", results)
	}
}
