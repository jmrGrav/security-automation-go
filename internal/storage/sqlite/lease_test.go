package sqlite

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/models"
)

func TestLeaseRepositoryIsScopeAware(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "lease-scope-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	repo := NewLeaseRepository(db)
	ctx := context.Background()
	expiresAt := time.Now().UTC().Add(time.Hour)

	if err := repo.AcquireLease(ctx, "scope-a", models.Lease{
		ID:           "lease-a",
		Owner:        "worker-a",
		Action:       "reconcile",
		EpochID:      "epoch-a",
		FencingToken: 1,
		ExpiresAt:    expiresAt,
	}); err != nil {
		t.Fatalf("acquire scope-a lease: %v", err)
	}
	if err := repo.AcquireLease(ctx, "scope-b", models.Lease{
		ID:           "lease-b",
		Owner:        "worker-b",
		Action:       "reconcile",
		EpochID:      "epoch-b",
		FencingToken: 2,
		ExpiresAt:    expiresAt,
	}); err != nil {
		t.Fatalf("acquire scope-b lease: %v", err)
	}

	leaseA, err := repo.GetActiveLease(ctx, "scope-a", "reconcile")
	if err != nil {
		t.Fatalf("get scope-a lease: %v", err)
	}
	if leaseA == nil || leaseA.ID != "lease-a" {
		t.Fatalf("expected scope-a lease, got %+v", leaseA)
	}

	leaseB, err := repo.GetActiveLease(ctx, "scope-b", "reconcile")
	if err != nil {
		t.Fatalf("get scope-b lease: %v", err)
	}
	if leaseB == nil || leaseB.ID != "lease-b" {
		t.Fatalf("expected scope-b lease, got %+v", leaseB)
	}

	if err := repo.ReleaseLease(ctx, "scope-a", "lease-a", "worker-a"); err != nil {
		t.Fatalf("release scope-a lease: %v", err)
	}
	leaseA, err = repo.GetActiveLease(ctx, "scope-a", "reconcile")
	if err != nil {
		t.Fatalf("get scope-a lease after release: %v", err)
	}
	if leaseA != nil {
		t.Fatalf("expected released lease to disappear, got %+v", leaseA)
	}
	if leaseB, err = repo.GetActiveLease(ctx, "scope-b", "reconcile"); err != nil || leaseB == nil {
		t.Fatalf("expected scope-b lease to remain visible, got %+v err=%v", leaseB, err)
	}
}

func TestLeaseRepositoryRenewLease(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	repo := NewLeaseRepository(db)
	ctx := context.Background()
	initial := time.Now().UTC().Add(10 * time.Minute)
	if err := repo.AcquireLease(ctx, "scope-a", models.Lease{
		ID:           "lease-a",
		Owner:        "worker-a",
		Action:       "reconcile",
		EpochID:      "epoch-a",
		FencingToken: 1,
		ExpiresAt:    initial,
	}); err != nil {
		t.Fatalf("acquire lease: %v", err)
	}

	renewed := initial.Add(20 * time.Minute)
	if err := repo.RenewLease(ctx, "scope-a", "lease-a", "worker-a", "epoch-a", 1, renewed); err != nil {
		t.Fatalf("renew lease: %v", err)
	}
	lease, err := repo.GetActiveLease(ctx, "scope-a", "reconcile")
	if err != nil {
		t.Fatalf("get renewed lease: %v", err)
	}
	if lease == nil || !lease.ExpiresAt.Equal(renewed) {
		t.Fatalf("expected renewed expiry, got %+v", lease)
	}

	// Test owner mismatch
	if err := repo.RenewLease(ctx, "scope-a", "lease-a", "wrong-worker", "epoch-a", 1, renewed.Add(time.Minute)); err == nil {
		t.Fatal("expected error on owner mismatch, got nil")
	}

	// Test fencing token mismatch
	if err := repo.RenewLease(ctx, "scope-a", "lease-a", "worker-a", "epoch-a", 2, renewed.Add(2*time.Minute)); err == nil {
		t.Fatal("expected error on fencing token mismatch, got nil")
	}

	// Test epoch mismatch
	if err := repo.RenewLease(ctx, "scope-a", "lease-a", "worker-a", "epoch-stale", 1, renewed.Add(3*time.Minute)); err == nil {
		t.Fatal("expected error on epoch mismatch, got nil")
	}
}

func TestLeaseRepositorySupportsLegacyEmptyScopeRows(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	expiresAt := time.Now().UTC().Add(time.Hour)
	if _, err := db.Conn().ExecContext(ctx, `
		INSERT INTO leases (scope_id, lease_id, owner, action, epoch_id, fencing_token, expires_at)
		VALUES ('', 'legacy-lease', 'worker-a', 'reconcile', 'epoch-a', 1, ?)
	`, expiresAt); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	// Manual normalization since DB.New already ran
	if err := db.NormalizeLeases(ctx); err != nil {
		t.Fatalf("normalize leases: %v", err)
	}

	repo := NewLeaseRepository(db)
	lease, err := repo.GetActiveLease(ctx, "default", "reconcile")
	if err != nil {
		t.Fatalf("get legacy lease: %v", err)
	}
	if lease == nil || lease.ID != "legacy-lease" {
		t.Fatalf("expected legacy lease fallback, got %+v", lease)
	}
	var scopeID string
	if err := db.Conn().QueryRowContext(ctx, "SELECT scope_id FROM leases WHERE lease_id = ?", "legacy-lease").Scan(&scopeID); err != nil {
		t.Fatalf("read migrated scope: %v", err)
	}
	if scopeID != "default" {
		t.Fatalf("expected legacy row to be normalized to 'default', got %q", scopeID)
	}

	if err := repo.ReleaseLease(ctx, "default", "legacy-lease", "worker-a"); err != nil {
		t.Fatalf("release legacy lease: %v", err)
	}
}
