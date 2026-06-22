package trustednetworks_test

import (
	"context"
	"errors"
	"testing"

	cfmodels "github.com/jm/security-automation-go/internal/cloudflare/models"
	csmodels "github.com/jm/security-automation-go/internal/crowdsec/models"
	. "github.com/jm/security-automation-go/internal/trustednetworks"
	"github.com/jm/security-automation-go/internal/trustednetworks/memstore"
)

type fakeCrowdSecSpoke struct {
	allowlist map[string][]csmodels.AllowlistEntry
	listErr   error
	addErr    error
	added     []csmodels.AllowlistEntry
}

func (f *fakeCrowdSecSpoke) ListAllowlist(_ context.Context, name string) ([]csmodels.AllowlistEntry, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.allowlist[name], nil
}

func (f *fakeCrowdSecSpoke) AddAllowlistEntry(_ context.Context, name string, entry csmodels.AllowlistEntry) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.allowlist[name] = append(f.allowlist[name], entry)
	f.added = append(f.added, entry)
	return nil
}

type fakeCloudflareSpoke struct {
	rules   []cfmodels.IPAccessRule
	listErr error
	addErr  error
	added   []cfmodels.IPAccessRule
}

func (f *fakeCloudflareSpoke) ListIPAccessRulesByNotePrefix(_ context.Context, _ string, _ string) ([]cfmodels.IPAccessRule, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.rules, nil
}

func (f *fakeCloudflareSpoke) AddIPAccessRuleWithMode(_ context.Context, _ string, value, notes, target, mode string) (string, error) {
	if f.addErr != nil {
		return "", f.addErr
	}
	rule := cfmodels.IPAccessRule{
		ID:    "rule-" + value,
		Mode:  mode,
		Notes: notes,
		Configuration: cfmodels.RuleConfiguration{
			Target: target,
			Value:  value,
		},
	}
	f.rules = append(f.rules, rule)
	f.added = append(f.added, rule)
	return rule.ID, nil
}

type fakeAuditSink struct {
	calls []string
}

func (f *fakeAuditSink) RecordTrustedNetworkAction(_ context.Context, action, target, value, detail string) error {
	f.calls = append(f.calls, action+":"+target+":"+value+":"+detail)
	return nil
}

func TestSync_ShadowMode_NeverMutatesSpokes(t *testing.T) {
	store := memstore.New()
	_ = store.Upsert(context.Background(), Entry{Value: "203.0.113.5", Label: "test"})

	cs := &fakeCrowdSecSpoke{allowlist: map[string][]csmodels.AllowlistEntry{}}
	cf := &fakeCloudflareSpoke{}
	reg := &Registry{
		Store:                 store,
		CrowdSec:              cs,
		CrowdSecAllowlistName: "my_allowlist",
		Cloudflare:            cf,
		CloudflareZoneID:      "zone-1",
		Mode:                  "shadow",
	}

	report, err := reg.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(cs.added) != 0 || len(cf.added) != 0 {
		t.Fatalf("shadow mode must never push: crowdsec=%v cloudflare=%v", cs.added, cf.added)
	}
	if report.Mode != "shadow" {
		t.Fatalf("expected report.Mode=shadow, got %q", report.Mode)
	}
}

func TestSync_EnforceMode_PushesAdditivelyToBothSpokes(t *testing.T) {
	store := memstore.New()
	_ = store.Upsert(context.Background(), Entry{Value: "203.0.113.5", Label: "office"})

	cs := &fakeCrowdSecSpoke{allowlist: map[string][]csmodels.AllowlistEntry{}}
	cf := &fakeCloudflareSpoke{}
	audit := &fakeAuditSink{}
	reg := &Registry{
		Store:                 store,
		CrowdSec:              cs,
		CrowdSecAllowlistName: "my_allowlist",
		Cloudflare:            cf,
		CloudflareZoneID:      "zone-1",
		Mode:                  "enforce",
		Audit:                 audit,
	}

	report, err := reg.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(cs.added) != 1 || cs.added[0].Value != "203.0.113.5" {
		t.Fatalf("expected crowdsec push, got %v", cs.added)
	}
	if len(cf.added) != 1 || cf.added[0].Configuration.Value != "203.0.113.5" || cf.added[0].Mode != "whitelist" {
		t.Fatalf("expected cloudflare whitelist push, got %v", cf.added)
	}
	if len(report.CrowdSec.Pushed) != 1 || len(report.Cloudflare.Pushed) != 1 {
		t.Fatalf("expected report to record 1 push per spoke, got %+v", report)
	}
	if len(audit.calls) != 2 {
		t.Fatalf("expected 2 audit records (one per spoke push), got %v", audit.calls)
	}
}

func TestSync_NeverPushesViaSpokeCrossTalk(t *testing.T) {
	// Even if a value exists in one spoke's remote state but not in the
	// registry, the other spoke must never be informed of it: both spokes
	// are driven solely from the registry, never from each other.
	store := memstore.New()
	_ = store.Upsert(context.Background(), Entry{Value: "203.0.113.9"})

	cs := &fakeCrowdSecSpoke{allowlist: map[string][]csmodels.AllowlistEntry{
		"my_allowlist": {{Value: "198.51.100.1", Comment: NotePrefix + "stale"}},
	}}
	cf := &fakeCloudflareSpoke{}
	reg := &Registry{
		Store: store, CrowdSec: cs, CrowdSecAllowlistName: "my_allowlist",
		Cloudflare: cf, CloudflareZoneID: "zone-1", Mode: "enforce",
	}

	if _, err := reg.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	for _, rule := range cf.added {
		if rule.Configuration.Value == "198.51.100.1" {
			t.Fatalf("cloudflare spoke must never receive crowdsec-only state: %v", cf.added)
		}
	}
}

func TestSync_DriftDetectedButNeverRemoved(t *testing.T) {
	store := memstore.New()
	// Registry is empty/doesn't contain the remote entry.
	cs := &fakeCrowdSecSpoke{allowlist: map[string][]csmodels.AllowlistEntry{
		"my_allowlist": {{Value: "198.51.100.1", Comment: NotePrefix + "orphaned"}},
	}}
	cf := &fakeCloudflareSpoke{rules: []cfmodels.IPAccessRule{
		{ID: "r1", Mode: "whitelist", Notes: NotePrefix + "orphaned", Configuration: cfmodels.RuleConfiguration{Target: "ip", Value: "198.51.100.1"}},
	}}
	audit := &fakeAuditSink{}
	reg := &Registry{
		Store: store, CrowdSec: cs, CrowdSecAllowlistName: "my_allowlist",
		Cloudflare: cf, CloudflareZoneID: "zone-1", Mode: "enforce", Audit: audit,
	}

	report, err := reg.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(report.CrowdSec.Drift) != 1 || report.CrowdSec.Drift[0] != "198.51.100.1" {
		t.Fatalf("expected crowdsec drift detected, got %+v", report.CrowdSec)
	}
	if len(report.Cloudflare.Drift) != 1 || report.Cloudflare.Drift[0] != "198.51.100.1" {
		t.Fatalf("expected cloudflare drift detected, got %+v", report.Cloudflare)
	}
	// Nothing must have been removed from either fake spoke's remote state.
	if len(cs.allowlist["my_allowlist"]) != 1 {
		t.Fatalf("expected crowdsec allowlist entry to remain present, got %v", cs.allowlist["my_allowlist"])
	}
	if len(cf.rules) != 1 {
		t.Fatalf("expected cloudflare rule to remain present, got %v", cf.rules)
	}
}

func TestSync_UntaggedManualEntriesAreNeverFlaggedOrTouched(t *testing.T) {
	store := memstore.New()
	cs := &fakeCrowdSecSpoke{allowlist: map[string][]csmodels.AllowlistEntry{
		"my_allowlist": {{Value: "10.0.0.1", Comment: "manually added by operator"}},
	}}
	reg := &Registry{Store: store, CrowdSec: cs, CrowdSecAllowlistName: "my_allowlist", Mode: "enforce"}

	report, err := reg.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(report.CrowdSec.Drift) != 0 {
		t.Fatalf("untagged manual entries must never be reported as drift, got %+v", report.CrowdSec.Drift)
	}
}

func TestSync_ErroredRegistryLoadAbortsEntirely(t *testing.T) {
	failingStore := &erroringStore{}
	cs := &fakeCrowdSecSpoke{allowlist: map[string][]csmodels.AllowlistEntry{}}
	reg := &Registry{Store: failingStore, CrowdSec: cs, CrowdSecAllowlistName: "my_allowlist", Mode: "enforce"}

	if _, err := reg.Sync(context.Background()); err == nil {
		t.Fatal("expected Sync to return an error when the registry fails to load")
	}
	if len(cs.added) != 0 {
		t.Fatalf("a failed registry load must never be treated as 'remove everything': got pushes %v", cs.added)
	}
}

type erroringStore struct{}

func (erroringStore) List(context.Context) ([]Entry, error) { return nil, errors.New("db down") }
func (erroringStore) Get(context.Context, string) (Entry, bool, error) {
	return Entry{}, false, nil
}
func (erroringStore) Upsert(context.Context, Entry) error  { return nil }
func (erroringStore) Remove(context.Context, string) error { return nil }

func TestSync_AlreadySyncedEntriesAreNotRepushed(t *testing.T) {
	store := memstore.New()
	_ = store.Upsert(context.Background(), Entry{Value: "203.0.113.5"})
	cs := &fakeCrowdSecSpoke{allowlist: map[string][]csmodels.AllowlistEntry{
		"my_allowlist": {{Value: "203.0.113.5", Comment: NotePrefix + "203.0.113.5"}},
	}}
	reg := &Registry{Store: store, CrowdSec: cs, CrowdSecAllowlistName: "my_allowlist", Mode: "enforce"}

	report, err := reg.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(cs.added) != 0 {
		t.Fatalf("expected no duplicate push for already-synced entry, got %v", cs.added)
	}
	if len(report.CrowdSec.AlreadySynced) != 1 {
		t.Fatalf("expected AlreadySynced to record the entry, got %+v", report.CrowdSec)
	}
}
