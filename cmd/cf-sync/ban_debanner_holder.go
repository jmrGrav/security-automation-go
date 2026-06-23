package main

import (
	"context"
	"errors"
	"sync"

	"github.com/jm/security-automation-go/internal/ui"
)

// errBanDebannerNotReady is returned when the holder's inner BanDebanner has
// not yet been set (e.g. the daemon's scoped DB/Cloudflare client wiring
// hasn't completed). The UI gate (banDebanActionsAvailable) checks the
// holder is non-nil, but the holder always exists once constructed in
// runtime.go — only its inner adapter populates later — so callers can still
// race this window and need a clear error rather than a silent no-op.
var errBanDebannerNotReady = errors.New("cloudflare deban capability not ready yet")

// lazyBanDebanner wraps a ui.BanDebanner that is populated after daemon
// startup, once the scoped runtime DB and Cloudflare enforcement client are
// available. Mirrors lazyBanLifecycleStore's pattern: the UI server goroutine
// starts before that wiring exists, so it must hold this indirection rather
// than a concrete *cleanup.Worker-backed adapter.
type lazyBanDebanner struct {
	mu    sync.RWMutex
	inner ui.BanDebanner
}

func (d *lazyBanDebanner) set(inner ui.BanDebanner) {
	d.mu.Lock()
	d.inner = inner
	d.mu.Unlock()
}

func (d *lazyBanDebanner) get() ui.BanDebanner {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.inner
}

func (d *lazyBanDebanner) DebanIP(ctx context.Context, ip, reason string) error {
	if inner := d.get(); inner != nil {
		return inner.DebanIP(ctx, ip, reason)
	}
	return errBanDebannerNotReady
}

func (d *lazyBanDebanner) ClearManagedBans(ctx context.Context, reason string) (ui.BanClearResult, error) {
	if inner := d.get(); inner != nil {
		return inner.ClearManagedBans(ctx, reason)
	}
	return ui.BanClearResult{}, errBanDebannerNotReady
}

var _ ui.BanDebanner = (*lazyBanDebanner)(nil)
