package registry

import (
	"github.com/jm/security-automation-go/internal/policy/bundles/manifest"
	"sync"
)

// Registry manages immutable policy bundles.
type Registry struct {
	mu      sync.RWMutex
	bundles map[string]manifest.BundleManifest // SHA256 -> Manifest
	active  string                             // Current SHA256
}

func New() *Registry {
	return &Registry{
		bundles: make(map[string]manifest.BundleManifest),
	}
}

func (r *Registry) Register(m manifest.BundleManifest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bundles[m.SHA256] = m
}

func (r *Registry) Activate(sha string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.active = sha
}

func (r *Registry) GetActive() (manifest.BundleManifest, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.bundles[r.active]
	return m, ok
}

func (r *Registry) List() []manifest.BundleManifest {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]manifest.BundleManifest, 0, len(r.bundles))
	for _, m := range r.bundles {
		out = append(out, m)
	}
	return out
}
