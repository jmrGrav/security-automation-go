//go:build soak

package chaos

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

func TestSoakHarness(t *testing.T) {
	db, err := sqlite.New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	repo := sqlite.NewEventRepository(db)
	outbox := sqlite.NewReportReservationStore(db)
	ctx := context.Background()
	base := time.Now().UTC()

	for i := 0; i < 250; i++ {
		ev := &events.Event{
			UID:           fmt.Sprintf("soak-%d", i),
			Timestamp:     base.Add(time.Duration(i) * time.Second),
			Category:      events.CategorySecurity,
			Type:          "soak_event",
			CorrelationID: "soak",
			Actor:         "soak",
			ScopeID:       "scope-soak",
			Payload:       []byte(`{"i":` + fmt.Sprint(i) + `}`),
		}
		if err := repo.Append(ctx, ev); err != nil {
			t.Fatalf("append event %d: %v", i, err)
		}
		if i%5 == 0 {
			reservation := reporting.ReportReservation{
				IP:             "203.0.113.10",
				Source:         "cloudflare_waf",
				IdempotencyKey: fmt.Sprintf("idem-%d", i),
				EvidenceID:     fmt.Sprintf("ev-%d", i),
				Status:         reporting.ReportStatusPending,
				ExpiresAt:      base.Add(time.Duration(i+1) * time.Minute),
			}
			if err := outbox.Reserve(ctx, reservation); err != nil {
				t.Fatalf("reserve outbox %d: %v", i, err)
			}
			if err := outbox.RecordAttempt(ctx, reservation.EvidenceID, reporting.ReportStatusFailed, "soak retry", base.Add(time.Duration(i+2)*time.Minute)); err != nil {
				t.Fatalf("record attempt %d: %v", i, err)
			}
		}
	}
}
