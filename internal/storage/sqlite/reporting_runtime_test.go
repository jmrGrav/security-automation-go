package sqlite

import (
	"context"
	"testing"
	"time"

	abexec "github.com/jm/security-automation-go/internal/abuseipdb/executor"
	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	rollbackmodels "github.com/jm/security-automation-go/internal/rollback/models"
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

type noOpReporter struct{}

func (noOpReporter) Execute(context.Context, []abmodels.ExecutableReport) error { return nil }

var _ abexec.Executor = noOpReporter{}

func TestReportingStoresConfigureWiresPersistence(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	stores := NewReportingStores(db)
	if stores == nil {
		t.Fatal("expected reporting stores")
	}

	service := reporting.New(noOpReporter{}, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	stores.Configure(service)
	service.SetClock(func() time.Time { return time.Date(2026, 6, 1, 17, 0, 0, 0, time.UTC) })

	event, err := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP:        "8.8.8.8",
		URI:       "/search?q=union+select+1",
		UserAgent: "sqlmap",
		Timestamp: time.Date(2026, 6, 1, 17, 0, 0, 0, time.UTC),
		Hits:      10,
		WindowSec: 300,
		RuleID:    "r1",
		Action:    "block",
		Source:    "cloudflare",
		Hostname:  "arleo.eu",
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !result.Reported {
		t.Fatalf("expected report through configured stores, got %+v", result)
	}

	var evidenceCount int
	if err := db.Conn().QueryRowContext(context.Background(), `SELECT count(*) FROM abuseipdb_reporting_evidence`).Scan(&evidenceCount); err != nil {
		t.Fatalf("count evidence: %v", err)
	}
	if evidenceCount < 2 {
		t.Fatalf("expected pending and success evidence rows, got %d", evidenceCount)
	}

	var outboxStatus string
	if err := db.Conn().QueryRowContext(context.Background(), `
		SELECT status
		FROM abuseipdb_report_outbox
		ORDER BY created_at DESC
		LIMIT 1
	`).Scan(&outboxStatus); err != nil {
		t.Fatalf("query outbox: %v", err)
	}
	if outboxStatus != reporting.ReportStatusReported {
		t.Fatalf("expected reported outbox status, got %s", outboxStatus)
	}
}

func TestReportingStoresNilSafe(t *testing.T) {
	if NewReportingStores(nil) != nil {
		t.Fatal("expected nil reporting stores for nil db")
	}

	// Configure must remain nil-safe for composition roots.
	stores := &ReportingStores{}
	stores.Configure(nil)
}

func TestReportReservationStoreMarkStatusReturnsErrorForMissingEvidenceID(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewReportReservationStore(db)
	err = store.MarkStatus(context.Background(), "missing-evidence", reporting.ReportStatusReported)
	if err == nil {
		t.Fatal("expected missing reservation error")
	}
}

func TestRollbackCheckpointStorePersistsScopeFromFirstScopedOperation(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewRollbackCheckpointStore(db)
	batch := rollbackBatchForTest()
	if err := store.SaveRollbackCheckpoint(context.Background(), batch); err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}

	var scopeID string
	if err := db.Conn().QueryRowContext(context.Background(), `SELECT scope_id FROM rollback_checkpoints WHERE batch_id = ?`, batch.ID).Scan(&scopeID); err != nil {
		t.Fatalf("query scope: %v", err)
	}
	if scopeID != "scope-a" {
		t.Fatalf("expected first scoped op to determine scope, got %q", scopeID)
	}
}

func rollbackBatchForTest() rollbackmodels.RollbackBatch {
	return rollbackmodels.RollbackBatch{
		ID:                 "rb-scope",
		OriginatingBatchID: "batch-a",
		Status:             rollbackmodels.StateExecuting,
		StartedAt:          time.Date(2026, 6, 1, 17, 0, 0, 0, time.UTC),
		Operations: []rollbackmodels.CompensationOperation{
			{OperationID: "op-1", ResourceType: "ip_access_rules"},
			{OperationID: "op-2", ScopeID: "scope-a", ResourceType: "ip_access_rules"},
		},
	}
}
