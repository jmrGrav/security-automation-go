package autodeban_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
	"github.com/jm/security-automation-go/internal/security/autodeban"
	"github.com/jm/security-automation-go/internal/security/reputation"
	"github.com/jm/security-automation-go/internal/security/trust"
)

// --- fakes ---

type fakeStore struct {
	mu      sync.Mutex
	entries map[string]banlifecycle.Entry
	marked  map[string]string // ip -> status
}

func newFakeStore(entries ...banlifecycle.Entry) *fakeStore {
	s := &fakeStore{entries: map[string]banlifecycle.Entry{}, marked: map[string]string{}}
	for _, e := range entries {
		s.entries[e.IP] = e
	}
	return s
}

func (s *fakeStore) Upsert(_ context.Context, e banlifecycle.Entry) error {
	return errors.New("autodeban must never call Upsert")
}

func (s *fakeStore) Get(_ context.Context, ip string) (banlifecycle.Entry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[ip]
	return e, ok, nil
}

func (s *fakeStore) Active(_ context.Context) ([]banlifecycle.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []banlifecycle.Entry
	for _, e := range s.entries {
		out = append(out, e)
	}
	return out, nil
}

func (s *fakeStore) Expired(_ context.Context, _ time.Time) ([]banlifecycle.Entry, error) {
	return nil, nil
}

func (s *fakeStore) Recent(_ context.Context, _ int) ([]banlifecycle.Entry, error) {
	return nil, nil
}

func (s *fakeStore) MarkStatus(_ context.Context, ip string, status string, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.marked[ip] = status
	return nil
}

func (s *fakeStore) RecidiveLevel(_ context.Context, ip string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entries[ip].RecidiveLevel, nil
}

func (s *fakeStore) RecordCleanupFailure(_ context.Context, ip string, errMsg string) error {
	return nil
}

func (s *fakeStore) statusOf(ip string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.marked[ip]
	return v, ok
}

type fakeDeleter struct {
	mu      sync.Mutex
	deleted []string
	err     error
}

func (f *fakeDeleter) DeleteIPAccessRule(_ context.Context, _ string, ruleID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.deleted = append(f.deleted, ruleID)
	return nil
}

func (f *fakeDeleter) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.deleted)
}

type fakeGate struct {
	decision reputation.Decision
}

func (g *fakeGate) EvaluateBan(_ context.Context, _ string, _ reputation.LocalSignal) reputation.Decision {
	return g.decision
}

// fakeCrowdSec implements autodeban.CrowdSecChecker directly (not via the
// ListActiveBans adapter) so tests can control true/false/error directly.
type fakeCrowdSec struct {
	active bool
	err    error
}

func (f *fakeCrowdSec) ActiveDecision(_ context.Context, _ string) (bool, error) {
	return f.active, f.err
}

type fakeEvidence struct {
	records []autodeban.EvidenceRecord
	err     error
}

func (f *fakeEvidence) Search(_ context.Context, opts autodeban.EvidenceSearchOptions) ([]autodeban.EvidenceRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	if opts.From.IsZero() {
		return f.records, nil
	}
	var out []autodeban.EvidenceRecord
	for _, r := range f.records {
		if !r.Timestamp.Before(opts.From) {
			out = append(out, r)
		}
	}
	return out, nil
}

type fakeAudit struct {
	mu      sync.Mutex
	records []map[string]string
	actions []string
}

func (f *fakeAudit) Record(action string, fields map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actions = append(f.actions, action)
	f.records = append(f.records, fields)
}

func (f *fakeAudit) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.records)
}

type fakeDebanEvidenceWriter struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *fakeDebanEvidenceWriter) WriteDebanEvidence(_ context.Context, _, _, _, _ string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.err
}

func (f *fakeDebanEvidenceWriter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// --- helpers ---

func baseEntry(ip string, now time.Time) banlifecycle.Entry {
	return banlifecycle.Entry{
		IP:         ip,
		Source:     "test",
		Reason:     "confidence_100",
		Confidence: 90,
		CreatedAt:  now.Add(-48 * time.Hour),
		ExpiresAt:  now.Add(48 * time.Hour),
		Duration:   96 * time.Hour,
		RuleID:     "rule-" + ip,
		Status:     banlifecycle.StatusActive,
	}
}

func newServiceForTest(t *testing.T, store banlifecycle.Store, gate autodeban.ReputationGate, cf autodeban.CloudflareDeleter, cs autodeban.CrowdSecChecker, ev autodeban.EvidenceStore, audit autodeban.AuditSink, debanEvi autodeban.DebanEvidenceWriter, trustReg *trust.Registry, cfg autodeban.Config, now time.Time) *autodeban.Service {
	t.Helper()
	svc := autodeban.NewService(store, gate, cf, cs, ev, audit, debanEvi, trustReg, cfg, nil)
	svc.SetClock(func() time.Time { return now })
	return svc
}

func enforceCfg() autodeban.Config {
	return autodeban.Config{Enabled: true, Mode: reputation.ModeEnforce}
}

func shadowCfg() autodeban.Config {
	return autodeban.Config{Enabled: true, Mode: reputation.ModeShadow}
}

// --- trigger test: no_local_evidence_ever, enforce mode, audit+evidence written ---

func TestScan_NoLocalEvidenceEver_Debans_WritesAuditAndEvidence(t *testing.T) {
	now := time.Now()
	ip := "1.2.3.4"
	store := newFakeStore(baseEntry(ip, now))
	deleter := &fakeDeleter{}
	audit := &fakeAudit{}
	debanEvi := &fakeDebanEvidenceWriter{}
	cs := &fakeCrowdSec{active: false}
	ev := &fakeEvidence{records: nil} // no events at all

	svc := newServiceForTest(t, store, nil, deleter, cs, ev, audit, debanEvi, trust.DefaultRegistry(), enforceCfg(), now)
	result := svc.Scan(context.Background())

	if len(result.Debanned) != 1 || result.Debanned[0] != ip {
		t.Fatalf("expected ip debanned, got %+v", result)
	}
	if deleter.calls() != 1 {
		t.Fatalf("expected real cloudflare delete in enforce mode, got %d calls", deleter.calls())
	}
	if status, ok := store.statusOf(ip); !ok || status != banlifecycle.StatusAutoDebanned {
		t.Fatalf("expected store marked auto_debanned, got %q ok=%v", status, ok)
	}
	if audit.count() != 1 {
		t.Fatalf("expected exactly one audit record, got %d", audit.count())
	}
	if debanEvi.count() != 1 {
		t.Fatalf("expected exactly one evidence write, got %d", debanEvi.count())
	}
}

// --- shadow mode: audit+evidence written, but zero real mutation ---

func TestScan_ShadowMode_NoRealMutation_ButAuditAndEvidenceWritten(t *testing.T) {
	now := time.Now()
	ip := "1.2.3.5"
	store := newFakeStore(baseEntry(ip, now))
	deleter := &fakeDeleter{}
	audit := &fakeAudit{}
	debanEvi := &fakeDebanEvidenceWriter{}
	cs := &fakeCrowdSec{active: false}
	ev := &fakeEvidence{records: nil}

	svc := newServiceForTest(t, store, nil, deleter, cs, ev, audit, debanEvi, trust.DefaultRegistry(), shadowCfg(), now)
	result := svc.Scan(context.Background())

	if len(result.Debanned) != 1 {
		t.Fatalf("expected shadow scan to still report the intended deban, got %+v", result)
	}
	if deleter.calls() != 0 {
		t.Fatalf("expected zero real cloudflare deletes in shadow mode, got %d", deleter.calls())
	}
	if _, ok := store.statusOf(ip); ok {
		t.Fatalf("expected store NOT marked in shadow mode")
	}
	if audit.count() != 1 {
		t.Fatalf("expected audit still written in shadow mode, got %d", audit.count())
	}
	if debanEvi.count() != 1 {
		t.Fatalf("expected evidence still written in shadow mode, got %d", debanEvi.count())
	}
}

// --- trigger: weak_signal_ban ---

func TestScan_WeakSignalBan_Debans(t *testing.T) {
	now := time.Now()
	ip := "1.2.3.6"
	entry := baseEntry(ip, now)
	entry.Confidence = 0
	store := newFakeStore(entry)
	ev := &fakeEvidence{records: []autodeban.EvidenceRecord{{Timestamp: now.Add(-1 * time.Hour), AbuseType: "benign_probe"}}}
	cs := &fakeCrowdSec{active: false}

	svc := newServiceForTest(t, store, nil, &fakeDeleter{}, cs, ev, &fakeAudit{}, &fakeDebanEvidenceWriter{}, trust.DefaultRegistry(), enforceCfg(), now)
	result := svc.Scan(context.Background())
	if len(result.Debanned) != 1 {
		t.Fatalf("expected weak_signal_ban to trigger deban, got %+v", result)
	}
}

// --- trigger: no_new_events ---

func TestScan_NoNewEvents_Debans(t *testing.T) {
	now := time.Now()
	ip := "1.2.3.7"
	store := newFakeStore(baseEntry(ip, now))
	ev := &fakeEvidence{records: []autodeban.EvidenceRecord{{Timestamp: now.Add(-30 * time.Hour), AbuseType: "scanner"}}}
	cs := &fakeCrowdSec{active: false}

	cfg := enforceCfg()
	cfg.NoNewEventsWindow = 24 * time.Hour
	svc := newServiceForTest(t, store, nil, &fakeDeleter{}, cs, ev, &fakeAudit{}, &fakeDebanEvidenceWriter{}, trust.DefaultRegistry(), cfg, now)
	result := svc.Scan(context.Background())
	if len(result.Debanned) != 1 {
		t.Fatalf("expected no_new_events to trigger deban, got %+v", result)
	}
}

// --- trigger: reputation_dropped ---

func TestScan_ReputationDropped_Debans(t *testing.T) {
	now := time.Now()
	ip := "1.2.3.8"
	store := newFakeStore(baseEntry(ip, now))
	// Recent event (within window) so the no_new_events trigger does not
	// fire first — we want to isolate the reputation-gate trigger path.
	ev := &fakeEvidence{records: []autodeban.EvidenceRecord{{Timestamp: now.Add(-1 * time.Hour), AbuseType: "benign_probe"}}}
	cs := &fakeCrowdSec{active: false}
	gate := &fakeGate{decision: reputation.Decision{AllowBan: false, Reason: "confidence_dropped"}}

	svc := newServiceForTest(t, store, gate, &fakeDeleter{}, cs, ev, &fakeAudit{}, &fakeDebanEvidenceWriter{}, trust.DefaultRegistry(), enforceCfg(), now)
	result := svc.Scan(context.Background())
	if len(result.Debanned) != 1 {
		t.Fatalf("expected reputation_dropped to trigger deban, got %+v", result)
	}
}

// --- still_warranted: nothing triggers, not debanned ---

func TestScan_StillWarranted_NotDebanned(t *testing.T) {
	now := time.Now()
	ip := "1.2.3.9"
	store := newFakeStore(baseEntry(ip, now))
	ev := &fakeEvidence{records: []autodeban.EvidenceRecord{{Timestamp: now.Add(-1 * time.Hour), AbuseType: "benign_probe"}}}
	cs := &fakeCrowdSec{active: false}
	gate := &fakeGate{decision: reputation.Decision{AllowBan: true}}

	svc := newServiceForTest(t, store, gate, &fakeDeleter{}, cs, ev, &fakeAudit{}, &fakeDebanEvidenceWriter{}, trust.DefaultRegistry(), enforceCfg(), now)
	result := svc.Scan(context.Background())
	if len(result.Debanned) != 0 {
		t.Fatalf("expected no deban when still warranted, got %+v", result)
	}
	if result.Excluded[ip] != "still_warranted" {
		t.Fatalf("expected still_warranted, got %q", result.Excluded[ip])
	}
}

// --- hard exclusion: protected_target ---

func TestScan_ProtectedIP_NeverDebanned(t *testing.T) {
	now := time.Now()
	ip := "127.0.0.1" // matches loopback/protected trust registry entries
	store := newFakeStore(baseEntry(ip, now))
	ev := &fakeEvidence{records: nil}
	cs := &fakeCrowdSec{active: false}

	svc := newServiceForTest(t, store, nil, &fakeDeleter{}, cs, ev, &fakeAudit{}, &fakeDebanEvidenceWriter{}, trust.DefaultRegistry(), enforceCfg(), now)
	result := svc.Scan(context.Background())
	if len(result.Debanned) != 0 {
		t.Fatalf("expected protected IP never debanned, got %+v", result)
	}
	if result.Excluded[ip] != "protected_target" {
		t.Fatalf("expected protected_target exclusion, got %q", result.Excluded[ip])
	}
}

// --- hard exclusion: unmanaged_rule (Store.Get miss) ---

func TestScan_UnmanagedRule_NeverDebanned(t *testing.T) {
	now := time.Now()
	ip := "1.2.3.10"
	// store.Active() returns the entry, but Get() is stubbed via a wrapper
	// that reports not-found, simulating an Active/Get disagreement.
	store := &getMissStore{fakeStore: newFakeStore(baseEntry(ip, now))}
	ev := &fakeEvidence{records: nil}
	cs := &fakeCrowdSec{active: false}

	svc := newServiceForTest(t, store, nil, &fakeDeleter{}, cs, ev, &fakeAudit{}, &fakeDebanEvidenceWriter{}, trust.DefaultRegistry(), enforceCfg(), now)
	result := svc.Scan(context.Background())
	if len(result.Debanned) != 0 {
		t.Fatalf("expected unmanaged rule never debanned, got %+v", result)
	}
	if result.Excluded[ip] != "unmanaged_rule" {
		t.Fatalf("expected unmanaged_rule exclusion, got %q", result.Excluded[ip])
	}
}

type getMissStore struct {
	*fakeStore
}

func (s *getMissStore) Get(_ context.Context, _ string) (banlifecycle.Entry, bool, error) {
	return banlifecycle.Entry{}, false, nil
}

// --- hard exclusion: active_recidive ---

func TestScan_ActiveRecidive_NeverDebanned(t *testing.T) {
	now := time.Now()
	ip := "1.2.3.11"
	entry := baseEntry(ip, now)
	entry.RecidiveLevel = 2
	entry.Duration = 100 * time.Hour
	entry.CreatedAt = now.Add(-10 * time.Hour) // 10% elapsed, well under 50% threshold
	store := newFakeStore(entry)
	ev := &fakeEvidence{records: nil}
	cs := &fakeCrowdSec{active: false}

	svc := newServiceForTest(t, store, nil, &fakeDeleter{}, cs, ev, &fakeAudit{}, &fakeDebanEvidenceWriter{}, trust.DefaultRegistry(), enforceCfg(), now)
	result := svc.Scan(context.Background())
	if len(result.Debanned) != 0 {
		t.Fatalf("expected active recidive never debanned, got %+v", result)
	}
	if result.Excluded[ip] != "active_recidive" {
		t.Fatalf("expected active_recidive exclusion, got %q", result.Excluded[ip])
	}
}

// --- hard exclusion: recent_waf_event ---

func TestScan_RecentWAFEvent_NeverDebanned(t *testing.T) {
	now := time.Now()
	ip := "1.2.3.12"
	store := newFakeStore(baseEntry(ip, now))
	ev := &fakeEvidence{records: []autodeban.EvidenceRecord{{Timestamp: now.Add(-1 * time.Hour), AbuseType: "exploit_attempt"}}}
	cs := &fakeCrowdSec{active: false}

	svc := newServiceForTest(t, store, nil, &fakeDeleter{}, cs, ev, &fakeAudit{}, &fakeDebanEvidenceWriter{}, trust.DefaultRegistry(), enforceCfg(), now)
	result := svc.Scan(context.Background())
	if len(result.Debanned) != 0 {
		t.Fatalf("expected recent WAF event to block deban, got %+v", result)
	}
	if result.Excluded[ip] != "recent_waf_event" {
		t.Fatalf("expected recent_waf_event exclusion, got %q", result.Excluded[ip])
	}
}

// --- hard exclusion: CrowdSec active decision ---

func TestScan_CrowdSecActive_NeverDebanned(t *testing.T) {
	now := time.Now()
	ip := "1.2.3.13"
	store := newFakeStore(baseEntry(ip, now))
	ev := &fakeEvidence{records: nil}
	cs := &fakeCrowdSec{active: true}

	svc := newServiceForTest(t, store, nil, &fakeDeleter{}, cs, ev, &fakeAudit{}, &fakeDebanEvidenceWriter{}, trust.DefaultRegistry(), enforceCfg(), now)
	result := svc.Scan(context.Background())
	if len(result.Debanned) != 0 {
		t.Fatalf("expected CrowdSec-active IP never debanned, got %+v", result)
	}
	if result.Excluded[ip] != "crowdsec_active_or_unknown" {
		t.Fatalf("expected crowdsec_active_or_unknown exclusion, got %q", result.Excluded[ip])
	}
}

// --- hard exclusion: CrowdSec unknown (error) — fail closed ---

func TestScan_CrowdSecUnknown_FailsClosed_NeverDebanned(t *testing.T) {
	now := time.Now()
	ip := "1.2.3.14"
	store := newFakeStore(baseEntry(ip, now))
	ev := &fakeEvidence{records: nil}
	cs := &fakeCrowdSec{active: false, err: errors.New("cscli unavailable")}

	svc := newServiceForTest(t, store, nil, &fakeDeleter{}, cs, ev, &fakeAudit{}, &fakeDebanEvidenceWriter{}, trust.DefaultRegistry(), enforceCfg(), now)
	result := svc.Scan(context.Background())
	if len(result.Debanned) != 0 {
		t.Fatalf("expected CrowdSec-unknown IP never debanned (fail closed), got %+v", result)
	}
	if result.Excluded[ip] != "crowdsec_active_or_unknown" {
		t.Fatalf("expected crowdsec_active_or_unknown exclusion on error, got %q", result.Excluded[ip])
	}
}

// --- CrowdSecListActiveBans adapter: nil func fails closed ---

func TestCrowdSecListActiveBans_NilFunc_FailsClosed(t *testing.T) {
	var adapter autodeban.CrowdSecListActiveBans
	active, err := adapter.ActiveDecision(context.Background(), "1.2.3.4")
	if err == nil {
		t.Fatalf("expected error for nil adapter func")
	}
	if active {
		t.Fatalf("expected active=false alongside the error")
	}
}

// --- CrowdSecListActiveBans adapter: list error fails closed ---

func TestCrowdSecListActiveBans_ListError_FailsClosed(t *testing.T) {
	adapter := autodeban.CrowdSecListActiveBans(func(ctx context.Context) ([]string, error) {
		return nil, errors.New("cscli timeout")
	})
	active, err := adapter.ActiveDecision(context.Background(), "1.2.3.4")
	if err == nil {
		t.Fatalf("expected error propagated")
	}
	if active {
		t.Fatalf("expected active=false alongside the error")
	}
}

// --- CrowdSecListActiveBans adapter: membership check works ---

func TestCrowdSecListActiveBans_MembershipCheck(t *testing.T) {
	adapter := autodeban.CrowdSecListActiveBans(func(ctx context.Context) ([]string, error) {
		return []string{"9.9.9.9", "1.2.3.4"}, nil
	})
	active, err := adapter.ActiveDecision(context.Background(), "1.2.3.4")
	if err != nil || !active {
		t.Fatalf("expected active=true, nil error, got active=%v err=%v", active, err)
	}
	active2, err2 := adapter.ActiveDecision(context.Background(), "5.5.5.5")
	if err2 != nil || active2 {
		t.Fatalf("expected active=false for unlisted ip, got active=%v err=%v", active2, err2)
	}
}

// --- Service never calls Store.Upsert ---

func TestScan_NeverCallsUpsert(t *testing.T) {
	now := time.Now()
	ip := "1.2.3.15"
	store := newFakeStore(baseEntry(ip, now))
	ev := &fakeEvidence{records: nil}
	cs := &fakeCrowdSec{active: false}

	svc := newServiceForTest(t, store, nil, &fakeDeleter{}, cs, ev, &fakeAudit{}, &fakeDebanEvidenceWriter{}, trust.DefaultRegistry(), enforceCfg(), now)
	// Scan should succeed and deban without ever invoking Upsert (which
	// returns an error in this fake if called at all).
	result := svc.Scan(context.Background())
	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors (proves Upsert was never called), got %+v", result.Errors)
	}
}

// --- disabled config: zero scanning ---

func TestScan_Disabled_NoOp(t *testing.T) {
	now := time.Now()
	ip := "1.2.3.16"
	store := newFakeStore(baseEntry(ip, now))
	svc := newServiceForTest(t, store, nil, &fakeDeleter{}, &fakeCrowdSec{}, &fakeEvidence{}, &fakeAudit{}, &fakeDebanEvidenceWriter{}, trust.DefaultRegistry(), autodeban.Config{Enabled: false}, now)
	result := svc.Scan(context.Background())
	if result.Considered != 0 || len(result.Debanned) != 0 {
		t.Fatalf("expected disabled config to no-op, got %+v", result)
	}
}
