package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/models"
)

func TestSQLiteErrorClassifiers(t *testing.T) {
	if isSQLiteBusy(nil) || isSQLiteConstraint(nil) || isSQLiteIOErr(nil) || isSQLiteCorrupt(nil) {
		t.Fatal("nil error must not classify as sqlite error")
	}
	if isSQLiteBusy(context.Canceled) || isSQLiteConstraint(context.Canceled) || isSQLiteIOErr(context.Canceled) || isSQLiteCorrupt(context.Canceled) {
		t.Fatal("generic error must not classify as sqlite error")
	}
}

func TestSQLiteLeaseAcquireIsIdempotentForSameOwner(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	repo := NewLeaseRepository(db)
	ctx := context.Background()
	lease := models.Lease{
		ID:           "lease-1",
		Owner:        "worker-a",
		Action:       "reconcile",
		EpochID:      "epoch-1",
		FencingToken: 1,
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
	}
	if err := repo.AcquireLease(ctx, "scope-a", lease); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := repo.AcquireLease(ctx, "scope-a", lease); err != nil {
		t.Fatalf("second acquire should be idempotent for same owner: %v", err)
	}
}
