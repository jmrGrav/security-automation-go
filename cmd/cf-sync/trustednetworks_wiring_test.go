package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/security/enrichment/asn"
	"github.com/jm/security-automation-go/internal/trustednetworks"
	"github.com/jm/security-automation-go/internal/trustednetworks/memstore"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestSeedTrustedNetworksFromASN_OnlyLoadsVerifiedEntries guards the
// fail-safe rule documented on seedTrustedNetworksFromASN: only CIDRs whose
// asn.RegistryEntry.Status() is RegistryStatusLoaded (verified against
// their source this session) are trusted into the allowlist seed. Entries
// like openai-chatgpt-user (RegistryStatusTooVolatile, CIDRs: nil) must
// never appear, since seeding unverified data into a security allowlist
// would silently widen what's trusted.
func TestSeedTrustedNetworksFromASN_OnlyLoadsVerifiedEntries(t *testing.T) {
	store := memstore.New()
	seedTrustedNetworksFromASN(context.Background(), store, discardLogger())

	entries, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	seeded := make(map[string]trustednetworks.Entry, len(entries))
	for _, e := range entries {
		seeded[e.Value] = e
	}

	// A known-loaded CIDR (Anthropic) must be present and correctly tagged.
	anthropicCIDR := "160.79.104.0/21"
	got, ok := seeded[anthropicCIDR]
	if !ok {
		t.Fatalf("expected %s (Anthropic, loaded) to be seeded, got entries: %+v", anthropicCIDR, seeded)
	}
	if got.Source != protectedNetworksImportSource {
		t.Errorf("expected Source=%q, got %q", protectedNetworksImportSource, got.Source)
	}
	if got.Label != "anthropic" {
		t.Errorf("expected Label=%q, got %q", "anthropic", got.Label)
	}

	// Verify every seeded value actually belongs to a RegistryStatusLoaded
	// entry — i.e. the seed never includes CIDRs from too-volatile or
	// source-unavailable entries.
	loadedCIDRs := make(map[string]bool)
	for _, e := range asn.DefaultRegistry() {
		if e.Status() != asn.RegistryStatusLoaded {
			continue
		}
		for _, cidr := range e.CIDRs {
			loadedCIDRs[cidr] = true
		}
	}
	for value := range seeded {
		if !loadedCIDRs[value] {
			t.Errorf("seeded value %q does not belong to any RegistryStatusLoaded ASN entry", value)
		}
	}

	// openai-chatgpt-user is documented as too_volatile with CIDRs: nil —
	// nothing from it should ever be seeded.
	for _, entry := range asn.DefaultRegistry() {
		if entry.Organization == "openai-chatgpt-user" && entry.Status() == asn.RegistryStatusLoaded {
			t.Fatalf("test assumption broken: openai-chatgpt-user is no longer too_volatile; update this test's expectations")
		}
	}
}

// TestSeedTrustedNetworksFromASN_IsIdempotent ensures repeated seeding
// (every daemon startup calls this) never duplicates entries or otherwise
// drifts the registry — Upsert must be a true upsert, not an insert.
func TestSeedTrustedNetworksFromASN_IsIdempotent(t *testing.T) {
	store := memstore.New()
	seedTrustedNetworksFromASN(context.Background(), store, discardLogger())
	first, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	seedTrustedNetworksFromASN(context.Background(), store, discardLogger())
	second, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(first) != len(second) {
		t.Fatalf("expected idempotent seeding, got %d entries then %d entries", len(first), len(second))
	}
}

// TestBuildTrustedNetworksRegistry_DisabledByConfig guards the safety
// invariant that the registry is never built when explicitly disabled in
// config — an operator who turns the feature off must never have it
// silently keep pushing to CrowdSec/Cloudflare allowlists.
func TestBuildTrustedNetworksRegistry_DisabledByConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TrustedNetworks.Enabled = false
	store := memstore.New()
	reg := buildTrustedNetworksRegistry(cfg, store, nil, nil, discardLogger(), nil)
	if reg != nil {
		t.Fatalf("expected nil registry when TrustedNetworks.Enabled is false, got %+v", reg)
	}
}

// TestBuildTrustedNetworksRegistry_DefaultConfigIsShadowMode documents the
// actual default: TrustedNetworks.Enabled is true out of the box (so drift
// detection runs from first boot), but Mode defaults to "shadow" — the
// registry must never enforce/mutate spokes without an explicit opt-in.
func TestBuildTrustedNetworksRegistry_DefaultConfigIsShadowMode(t *testing.T) {
	cfg := config.DefaultConfig()
	store := memstore.New()
	reg := buildTrustedNetworksRegistry(cfg, store, nil, nil, discardLogger(), nil)
	if reg == nil {
		t.Fatal("expected non-nil registry under default config (TrustedNetworks.Enabled defaults true)")
	}
	if got := reg.EffectiveMode(); got != "shadow" {
		t.Fatalf("expected default EffectiveMode()=shadow, got %q", got)
	}
}

// TestBuildTrustedNetworksRegistry_DefaultsToShadowMode guards the same
// safety invariant as ReputationPolicyConfig.EffectiveMode and
// trustednetworks.Registry.EffectiveMode: an empty or unrecognized Mode
// string must resolve to "shadow", never silently to "enforce".
func TestBuildTrustedNetworksRegistry_DefaultsToShadowMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TrustedNetworks.Enabled = true
	cfg.TrustedNetworks.Mode = "" // not set — must default safely
	store := memstore.New()

	reg := buildTrustedNetworksRegistry(cfg, store, nil, nil, discardLogger(), nil)
	if reg == nil {
		t.Fatal("expected non-nil registry when TrustedNetworks.Enabled is true")
	}
	if got := reg.EffectiveMode(); got != "shadow" {
		t.Fatalf("expected EffectiveMode()=shadow for unset Mode, got %q", got)
	}
}

// TestBuildTrustedNetworksRegistry_NilStoreNeverBuilds guards the registry
// doc comment's invariant: the registry must never run against a missing
// source of truth, so a nil store (e.g. SQLite unavailable) must yield a
// nil registry rather than one that silently no-ops on every Sync call.
func TestBuildTrustedNetworksRegistry_NilStoreNeverBuilds(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TrustedNetworks.Enabled = true
	reg := buildTrustedNetworksRegistry(cfg, nil, nil, nil, discardLogger(), nil)
	if reg != nil {
		t.Fatalf("expected nil registry for nil store, got %+v", reg)
	}
}

// TestStartTrustedNetworksSync_NilRegistryIsNoOp ensures the periodic sync
// launcher tolerates a nil registry (disabled feature / no SQLite) without
// panicking or starting a goroutine that spins on a nil receiver.
func TestStartTrustedNetworksSync_NilRegistryIsNoOp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Must return immediately without starting any goroutine; if this
	// panics or hangs, the test runner will catch it.
	startTrustedNetworksSync(ctx, discardLogger(), nil, 0)
}

// TestBuildTrustedNetworksRegistry_NeverWiresCrowdSecSpoke is the runtime
// guard for the architectural change in this package: the cf-sync daemon
// runs as the unprivileged security-automation user and can never read
// /etc/crowdsec/local_api_credentials.yaml, so it must never invoke cscli
// itself. reg.CrowdSec must always be nil regardless of config — the
// CrowdSec spoke's reconcile now runs exclusively inside the separate
// root-owned cf-allowlist-sync helper. This is the strong guarantee: a
// static grep for ListAllowlist/AddAllowlistEntry call sites is brittle
// (registry.go and internal/app legitimately reference them as the shared
// implementation), but "who supplies the spoke" is unambiguous here.
func TestBuildTrustedNetworksRegistry_NeverWiresCrowdSecSpoke(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TrustedNetworks.Enabled = true
	cfg.TrustedNetworks.Mode = "enforce"
	cfg.TrustedNetworks.CrowdSec.Enabled = true
	cfg.TrustedNetworks.CrowdSec.AllowlistName = "my_allowlist"
	cfg.CrowdSec.BinPath = "cscli"
	store := memstore.New()

	reg := buildTrustedNetworksRegistry(cfg, store, nil, nil, discardLogger(), nil)
	if reg == nil {
		t.Fatal("expected non-nil registry under enabled config")
	}
	if reg.CrowdSec != nil {
		t.Fatalf("cf-sync daemon must never wire a CrowdSec spoke (no cscli permission) — got non-nil CrowdSec spoke: %#v", reg.CrowdSec)
	}
	if reg.CrowdSecAllowlistName != "" {
		t.Fatalf("expected empty CrowdSecAllowlistName on the daemon's registry, got %q", reg.CrowdSecAllowlistName)
	}

	// Sanity: Sync must therefore report the CrowdSec spoke as disabled,
	// never silently "enabled with zero entries".
	report, err := reg.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if report.CrowdSec.Enabled {
		t.Fatalf("expected report.CrowdSec.Enabled=false from the daemon's own Sync pass, got %#v", report.CrowdSec)
	}
}
