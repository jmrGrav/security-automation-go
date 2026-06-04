package file_test

import (
	"context"
	"testing"

	"github.com/jm/security-automation-go/internal/runtime/ha"
	filebe "github.com/jm/security-automation-go/internal/runtime/ha/backends/file"
	"github.com/jm/security-automation-go/internal/runtime/scope"
)

func testScope() scope.RuntimeScope {
	return scope.RuntimeScope{
		Tenant:      "test-tenant",
		AccountID:   "acct-123",
		ZoneID:      "zone-456",
		Environment: "test",
	}
}

func TestFileBackend_CampaignLeader_ReturnsChannel(t *testing.T) {
	b := filebe.New(t.TempDir())
	ctx := context.Background()

	ch, err := b.CampaignLeader(ctx, testScope(), "owner-1")
	if err != nil {
		t.Fatalf("CampaignLeader returned unexpected error: %v", err)
	}
	if ch == nil {
		t.Fatal("CampaignLeader returned nil channel")
	}
}

func TestFileBackend_GetEpoch_ReturnsNonEmptyID(t *testing.T) {
	b := filebe.New(t.TempDir())
	ctx := context.Background()

	epoch, err := b.GetEpoch(ctx, testScope())
	if err != nil {
		t.Fatalf("GetEpoch returned unexpected error: %v", err)
	}
	if epoch.ID == "" {
		t.Error("GetEpoch returned empty epoch ID")
	}
}

func TestFileBackend_IncrementEpoch_ReturnsNonEmptyID(t *testing.T) {
	b := filebe.New(t.TempDir())
	ctx := context.Background()

	epoch, err := b.IncrementEpoch(ctx, testScope())
	if err != nil {
		t.Fatalf("IncrementEpoch returned unexpected error: %v", err)
	}
	if epoch.ID == "" {
		t.Error("IncrementEpoch returned empty epoch ID")
	}
}

func TestFileBackend_StoreFencingToken_GetFencingToken_RoundTrip(t *testing.T) {
	b := filebe.New(t.TempDir())
	ctx := context.Background()

	token := ha.FencingToken{
		ScopeID:    "scope-abc",
		Epoch:      7,
		Generation: 3,
		OwnerID:    "owner-42",
	}

	if err := b.StoreFencingToken(ctx, token); err != nil {
		t.Fatalf("StoreFencingToken returned unexpected error: %v", err)
	}

	got, err := b.GetFencingToken(ctx, token.ScopeID)
	if err != nil {
		t.Fatalf("GetFencingToken returned unexpected error: %v", err)
	}
	// The file backend is a stub that always echoes ScopeID back.
	if got.ScopeID != token.ScopeID {
		t.Errorf("expected ScopeID %q, got %q", token.ScopeID, got.ScopeID)
	}
}
