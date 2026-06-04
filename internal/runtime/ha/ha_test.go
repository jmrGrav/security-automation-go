package ha_test

import (
	"context"
	"testing"

	"github.com/jm/security-automation-go/internal/runtime/ha"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/scope"
)

// stubBackend implements CoordinationBackend for testing.
type stubBackend struct{}

func (s *stubBackend) CampaignLeader(_ context.Context, _ scope.RuntimeScope, _ string) (chan struct{}, error) {
	ch := make(chan struct{})
	return ch, nil
}

func (s *stubBackend) GetFencingToken(_ context.Context, scopeID string) (ha.FencingToken, error) {
	return ha.FencingToken{ScopeID: scopeID}, nil
}

func (s *stubBackend) StoreFencingToken(_ context.Context, _ ha.FencingToken) error {
	return nil
}

func (s *stubBackend) GetEpoch(_ context.Context, _ scope.RuntimeScope) (models.Epoch, error) {
	return models.Epoch{ID: "epoch-1"}, nil
}

func (s *stubBackend) IncrementEpoch(_ context.Context, _ scope.RuntimeScope) (models.Epoch, error) {
	return models.Epoch{ID: "epoch-2"}, nil
}

func TestNewLeaseCoordinator_NotNil(t *testing.T) {
	backend := &stubBackend{}
	lc := ha.NewLeaseCoordinator(backend, "owner-1")
	if lc == nil {
		t.Fatal("expected non-nil LeaseCoordinator")
	}
}

func TestFencingToken_ZeroValue(t *testing.T) {
	var ft ha.FencingToken
	if ft.ScopeID != "" {
		t.Errorf("expected empty ScopeID, got %q", ft.ScopeID)
	}
	if ft.Epoch != 0 {
		t.Errorf("expected zero Epoch, got %d", ft.Epoch)
	}
	if ft.Generation != 0 {
		t.Errorf("expected zero Generation, got %d", ft.Generation)
	}
	if ft.OwnerID != "" {
		t.Errorf("expected empty OwnerID, got %q", ft.OwnerID)
	}
}

func TestNewLeaseCoordinator_MultipleInstances(t *testing.T) {
	backend := &stubBackend{}
	lc1 := ha.NewLeaseCoordinator(backend, "owner-1")
	lc2 := ha.NewLeaseCoordinator(backend, "owner-2")
	if lc1 == lc2 {
		t.Error("expected distinct LeaseCoordinator instances")
	}
}
