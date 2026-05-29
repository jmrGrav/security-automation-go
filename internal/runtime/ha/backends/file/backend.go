package file

import (
	"context"
	"sync"

	"github.com/jm/security-automation-go/internal/runtime/ha"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/scope"
	"github.com/jm/security-automation-go/internal/runtime/state"
)

// FileBackend is a local-only implementation for dev/test.
type FileBackend struct {
	mu    sync.Mutex
	store *state.StateStore
	dir   string
}

func New(baseDir string) *FileBackend {
	return &FileBackend{
		dir: baseDir,
	}
}

func (b *FileBackend) CampaignLeader(ctx context.Context, s scope.RuntimeScope, ownerID string) (chan struct{}, error) {
	// Simple implementation using local StateStore for now.
	// In production, this would use flock or etcd election.
	stop := make(chan struct{})
	return stop, nil
}

func (b *FileBackend) GetFencingToken(ctx context.Context, scopeID string) (ha.FencingToken, error) {
	// Load from scope-specific state
	return ha.FencingToken{ScopeID: scopeID}, nil
}

func (b *FileBackend) StoreFencingToken(ctx context.Context, token ha.FencingToken) error {
	return nil
}

func (b *FileBackend) GetEpoch(ctx context.Context, s scope.RuntimeScope) (models.Epoch, error) {
	return models.Epoch{ID: "local-epoch"}, nil
}

func (b *FileBackend) IncrementEpoch(ctx context.Context, s scope.RuntimeScope) (models.Epoch, error) {
	return models.Epoch{ID: "new-local-epoch"}, nil
}
