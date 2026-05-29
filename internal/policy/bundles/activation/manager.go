package activation

import (
	"context"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/policy/bundles/manifest"
	"github.com/jm/security-automation-go/internal/policy/bundles/registry"
	"github.com/jm/security-automation-go/internal/policy/bundles/signing"
	"github.com/jm/security-automation-go/internal/policy/bundles/trust"
)

// Manager handles the trusted activation of policy bundles.
type Manager struct {
	registry *registry.Registry
	trust    *trust.Store
}

func NewManager(r *registry.Registry, s *trust.Store) *Manager {
	return &Manager{
		registry: r,
		trust:    s,
	}
}

// Activate validates and swaps the current policy bundle.
func (m *Manager) Activate(ctx context.Context, newManifest manifest.BundleManifest) error {
	const op = "policy.bundles.activation.Activate"

	// 1. Verify Signature
	verifier := signing.NewVerifier(m.trust.AllKeys())
	if err := verifier.Verify(newManifest); err != nil {
		return apperr.Wrap(op, err)
	}

	// 2. TODO: Verify Manifest Integrity (Hash Rego files)

	// 3. TODO: Verify Compatibility

	// 4. Register and Activate
	m.registry.Register(newManifest)
	m.registry.Activate(newManifest.SHA256)

	return nil
}

// Rollback reverts to a previously registered bundle.
func (m *Manager) Rollback(ctx context.Context, sha string) error {
	const op = "policy.bundles.activation.Rollback"
	// TODO: verify existence in registry and swap active
	m.registry.Activate(sha)
	return nil
}
