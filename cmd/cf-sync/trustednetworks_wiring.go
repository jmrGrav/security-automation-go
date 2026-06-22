package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	cfpkg "github.com/jm/security-automation-go/internal/cloudflare"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	runtimemodels "github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/security/enrichment/asn"
	"github.com/jm/security-automation-go/internal/trustednetworks"
)

// protectedNetworksImportSource tags every entry seeded from the Protected
// Networks ASN registry, so it is distinguishable in audits/exports from
// operator-curated entries added directly to the store.
const protectedNetworksImportSource = "protected_networks_import"

// seedTrustedNetworksFromASN upserts every CIDR from asn.DefaultRegistry()
// whose Status() is RegistryStatusLoaded into store, tagged with
// protectedNetworksImportSource. These are known-good crawler/monitoring/
// provider ranges (Anthropic, OpenAI, GitHub Copilot, Cloudflare, etc.) —
// allowlisting them is a pure security win since it only ever reduces false
// positives, never reduces protection. Entries whose Status() is
// TooVolatile or SourceUnavailable are deliberately skipped: seeding
// unverified or stale CIDRs into an allowlist would trust data that hasn't
// been confirmed against its source this session.
//
// Upsert is idempotent (ON CONFLICT update), so calling this on every
// startup is safe and keeps the registry in sync as DefaultRegistry grows.
func seedTrustedNetworksFromASN(ctx context.Context, store trustednetworks.Store, logger *slog.Logger) {
	if store == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	now := time.Now().UTC()
	for _, entry := range asn.DefaultRegistry() {
		if entry.Status() != asn.RegistryStatusLoaded {
			continue
		}
		for _, cidr := range entry.CIDRs {
			e := trustednetworks.Entry{
				Value:     cidr,
				Label:     entry.Organization,
				Source:    protectedNetworksImportSource,
				Comment:   fmt.Sprintf("kind=%s verified=%s", entry.Kind, entry.LastVerified),
				CreatedAt: now,
				UpdatedAt: now,
			}
			if err := store.Upsert(ctx, e); err != nil {
				logger.Warn("trusted networks: failed to seed ASN entry", "value", cidr, "organization", entry.Organization, "error", err)
			}
		}
	}
}

// trustedNetworksJournalAuditSink adapts a journal.JournalStore to
// trustednetworks.AuditSink's RecordTrustedNetworkAction shape, mirroring
// autodebanJournalAuditSink in autodeban_wiring.go.
type trustedNetworksJournalAuditSink struct {
	journal journal.JournalStore
}

func (s *trustedNetworksJournalAuditSink) RecordTrustedNetworkAction(ctx context.Context, action, target, value, detail string) error {
	if s == nil || s.journal == nil {
		return nil
	}
	return s.journal.Append(runtimemodels.AuditEvent{
		Timestamp: time.Now().UTC(),
		Status:    "completed",
		Target:    target,
		Metadata: map[string]any{
			"event":  action,
			"value":  value,
			"detail": detail,
		},
	})
}

var _ trustednetworks.AuditSink = (*trustedNetworksJournalAuditSink)(nil)

// buildTrustedNetworksRegistry constructs the hub-and-spoke registry from
// config and the already-built spoke clients. store may be nil when SQLite
// is unavailable, in which case the registry is not built at all (the
// registry must never run against a missing source of truth — see
// Registry.Sync's doc comment on why a load failure is a hard abort, not an
// empty-registry no-op).
//
// The CrowdSec spoke is deliberately NEVER wired here (reg.CrowdSec stays
// nil). The cf-sync daemon runs as the unprivileged security-automation
// user and cannot read /etc/crowdsec/local_api_credentials.yaml
// (root:root 0600), so it must never attempt to invoke cscli itself. The
// CrowdSec spoke's reconcile now runs entirely inside the separate
// root-owned cf-allowlist-sync helper (see cmd/cf-allowlist-sync), which
// persists its result to SQLite via trustednetworks.CrowdSecStatusStore.
// This registry's Sync calls only ever touch the Cloudflare spoke; CrowdSec
// status is read independently from that persisted record (see
// trustedNetworksView in internal/ui).
func buildTrustedNetworksRegistry(cfg *config.Config, store trustednetworks.Store, cfEnforcer cfpkg.EnforcementClient, auditJournal journal.JournalStore, logger *slog.Logger, cache *trustednetworks.ReportCache) *trustednetworks.Registry {
	if cfg == nil || !cfg.TrustedNetworks.Enabled || store == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}

	reg := &trustednetworks.Registry{
		Store:  store,
		Mode:   cfg.TrustedNetworks.EffectiveMode(),
		Audit:  &trustedNetworksJournalAuditSink{journal: auditJournal},
		Logger: logger,
		Cache:  cache,
	}

	if cfg.TrustedNetworks.Cloudflare.Enabled && cfEnforcer != nil {
		zoneID := cfg.TrustedNetworks.Cloudflare.ZoneID
		if zoneID == "" {
			zoneID = cfg.Cloudflare.ZoneID
		}
		if zoneID != "" {
			reg.Cloudflare = cfEnforcer
			reg.CloudflareZoneID = zoneID
		}
	}

	return reg
}

// startTrustedNetworksSync launches the periodic hub-and-spoke reconcile
// loop. It is a no-op if reg is nil (e.g. SQLite unavailable or the feature
// is disabled in config).
func startTrustedNetworksSync(ctx context.Context, logger *slog.Logger, reg *trustednetworks.Registry, interval time.Duration) {
	if reg == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = 10 * time.Minute
	}

	go func() {
		runTrustedNetworksSyncOnce(ctx, logger, reg)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runTrustedNetworksSyncOnce(ctx, logger, reg)
			}
		}
	}()
}

func runTrustedNetworksSyncOnce(parent context.Context, logger *slog.Logger, reg *trustednetworks.Registry) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	report, err := reg.Sync(ctx)
	if err != nil {
		logger.Warn("trusted networks sync failed", "error", err)
		return
	}
	if len(report.CrowdSec.Pushed) > 0 || len(report.Cloudflare.Pushed) > 0 ||
		len(report.CrowdSec.Drift) > 0 || len(report.Cloudflare.Drift) > 0 ||
		len(report.CrowdSec.Errors) > 0 || len(report.Cloudflare.Errors) > 0 {
		logger.Info("trusted networks sync complete",
			"mode", report.Mode,
			"registry_count", report.RegistryCount,
			"crowdsec_pushed", report.CrowdSec.Pushed,
			"crowdsec_drift", report.CrowdSec.Drift,
			"crowdsec_errors", report.CrowdSec.Errors,
			"cloudflare_pushed", report.Cloudflare.Pushed,
			"cloudflare_drift", report.Cloudflare.Drift,
			"cloudflare_errors", report.Cloudflare.Errors,
		)
	} else {
		logger.Debug("trusted networks sync complete", "mode", report.Mode, "registry_count", report.RegistryCount)
	}
}
