package execution

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/betterstack"
	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/runtime/breaker"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	rmodels "github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/security/reputation"
	"github.com/jm/security-automation-go/internal/security/trust"
	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type spyMutator struct {
	calls int
}

func (m *spyMutator) Execute(MutationOperation) (string, error) {
	m.calls++
	return "ok", nil
}

func (m *spyMutator) DryRun(MutationOperation) string { return "dry-run" }

type blockingMutator struct {
	called  chan struct{}
	release chan struct{}
}

func (m *blockingMutator) Execute(op MutationOperation) (string, error) {
	return m.ExecuteContext(context.Background(), op)
}

func (m *blockingMutator) ExecuteContext(ctx context.Context, _ MutationOperation) (string, error) {
	close(m.called)
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-m.release:
		return "ok", nil
	}
}

func (m *blockingMutator) DryRun(MutationOperation) string { return "blocking" }

type memoryJournal struct {
	events []rmodels.AuditEvent
}

func (m *memoryJournal) Append(event rmodels.AuditEvent) error {
	m.events = append(m.events, event)
	return nil
}

func (m *memoryJournal) List() ([]rmodels.AuditEvent, error) {
	out := make([]rmodels.AuditEvent, len(m.events))
	copy(out, m.events)
	return out, nil
}

type fixedChecker struct {
	result reputation.Result
	err    error
	calls  int
}

func (c *fixedChecker) Check(context.Context, netip.Addr) (reputation.Result, error) {
	c.calls++
	return c.result, c.err
}

type fakeLeaseLookup struct {
	scopeID string
	active  *rmodels.Lease
}

func (l fakeLeaseLookup) GetActiveLease(_ context.Context, scopeID string, action string) (*rmodels.Lease, error) {
	if l.active == nil || l.scopeID != scopeID || l.active.Action != action {
		return nil, nil
	}
	return l.active, nil
}

type rotatingLeaseLookup struct {
	scopeID string
	leases  []*rmodels.Lease
	calls   int
}

func (l *rotatingLeaseLookup) GetActiveLease(_ context.Context, scopeID string, action string) (*rmodels.Lease, error) {
	if l.scopeID != scopeID || len(l.leases) == 0 {
		return nil, nil
	}
	idx := l.calls
	if idx >= len(l.leases) {
		idx = len(l.leases) - 1
	}
	l.calls++
	lease := l.leases[idx]
	if lease == nil || lease.Action != action {
		return nil, nil
	}
	return lease, nil
}

type fakeBetterStackClient struct {
	events []betterstack.Event
}

func (f *fakeBetterStackClient) Send(_ context.Context, event betterstack.Event) error {
	f.events = append(f.events, event)
	return nil
}

func TestGovernedExecutorSuppressionPath(t *testing.T) {
	reg := resources.NewRegistry()
	j := &memoryJournal{}
	exec := NewGovernedExecutor(j, breaker.New(5, time.Minute, time.Second), reg)
	mut := &spyMutator{}
	exec.RegisterMutator("ip_access_rules", mut)

	checker := &fixedChecker{result: reputation.Result{
		IP:        netip.MustParseAddr("8.8.8.8"),
		Provider:  "abuseipdb",
		Score:     12,
		CheckedAt: time.Now().UTC(),
	}}
	guard := NewCloudflarePropagationGuard(checker, trust.DefaultRegistry())
	exec.SetSecurityGuard(guard)

	recorder := &sinks.RecorderSink{}
	bs := &fakeBetterStackClient{}
	exec.SetTelemetrySink(sinks.NewMulti(
		sinks.NewPrometheus(),
		recorder,
		sinks.NewBetterStack(bs),
	))

	beforeSuppressed := testutil.ToFloat64(metrics.SecurityFalsePositiveSuppressedTotal)
	beforeLow := testutil.ToFloat64(metrics.SecurityLowSignalSuppressedTotal)

	batch := MutationBatch{
		ID:     "batch-1",
		PlanID: "plan-1",
		Operations: []MutationOperation{{
			OperationID:  "op-1",
			Type:         "create",
			ResourceType: "ip_access_rules",
			Payload:      map[string]any{"configuration": map[string]any{"value": "8.8.8.8"}},
		}},
	}

	err := exec.ExecuteBatch(context.Background(), batch)
	if err == nil {
		t.Fatal("expected guarded batch to fail")
	}
	if mut.calls != 0 {
		t.Fatalf("mutator should not have been called, got %d", mut.calls)
	}
	if checker.calls != 1 {
		t.Fatalf("expected one reputation lookup, got %d", checker.calls)
	}
	events, _ := j.List()
	if len(events) == 0 {
		t.Fatal("expected audit event to be written")
	}
	last := events[len(events)-1]
	if last.Status != "quarantined" {
		t.Fatalf("expected quarantined audit status, got %s", last.Status)
	}
	if last.Metadata["suppression_reason"] == "" {
		t.Fatalf("expected suppression reason in metadata, got %#v", last.Metadata)
	}
	if len(recorder.Events) != 1 {
		t.Fatalf("expected one telemetry event, got %d", len(recorder.Events))
	}
	if recorder.Events[0].Propagated {
		t.Fatal("expected suppression telemetry to mark propagated=false")
	}
	if recorder.Events[0].SuppressionReason == "" {
		t.Fatal("expected suppression reason in telemetry")
	}
	if len(bs.events) != 1 {
		t.Fatalf("expected one BetterStack event, got %d", len(bs.events))
	}
	if got := testutil.ToFloat64(metrics.SecurityFalsePositiveSuppressedTotal); got <= beforeSuppressed {
		t.Fatal("expected suppression metric increment")
	}
	if got := testutil.ToFloat64(metrics.SecurityLowSignalSuppressedTotal); got <= beforeLow {
		t.Fatal("expected low-signal metric increment")
	}
}

func TestGovernedExecutorAllowsHighReputationPropagation(t *testing.T) {
	reg := resources.NewRegistry()
	j := &memoryJournal{}
	exec := NewGovernedExecutor(j, breaker.New(5, time.Minute, time.Second), reg)
	mut := &spyMutator{}
	exec.RegisterMutator("ip_access_rules", mut)

	checker := &fixedChecker{result: reputation.Result{
		IP:        netip.MustParseAddr("8.8.8.8"),
		Provider:  "abuseipdb",
		Score:     90,
		CheckedAt: time.Now().UTC(),
	}}
	guard := NewCloudflarePropagationGuard(checker, trust.DefaultRegistry())
	exec.SetSecurityGuard(guard)

	recorder := &sinks.RecorderSink{}
	exec.SetTelemetrySink(recorder)

	batch := MutationBatch{
		ID:     "batch-2",
		PlanID: "plan-2",
		Operations: []MutationOperation{{
			OperationID:  "op-2",
			Type:         "create",
			ResourceType: "ip_access_rules",
			Payload:      map[string]any{"configuration": map[string]any{"value": "8.8.8.8"}},
		}},
	}

	if err := exec.ExecuteBatch(context.Background(), batch); err != nil {
		t.Fatalf("unexpected execution failure: %v", err)
	}
	if mut.calls != 1 {
		t.Fatalf("expected mutator call, got %d", mut.calls)
	}
	if len(recorder.Events) != 0 {
		t.Fatalf("expected no suppression telemetry on allowed path, got %d", len(recorder.Events))
	}
}

func TestGovernedExecutorLostLeaseBeforeBatchSkipsMutator(t *testing.T) {
	reg := resources.NewRegistry()
	j := &memoryJournal{}
	exec := NewGovernedExecutor(j, breaker.New(5, time.Minute, time.Second), reg)
	mut := &spyMutator{}
	exec.RegisterMutator("ip_access_rules", mut)

	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errors.New("lost lease: heartbeat failed"))
	err := exec.ExecuteBatch(ctx, MutationBatch{
		ID: "batch-lost-before",
		Operations: []MutationOperation{{
			OperationID:  "op-1",
			Type:         "create",
			ResourceType: "ip_access_rules",
		}},
	})
	if err == nil {
		t.Fatal("expected lost lease execution error")
	}
	if mut.calls != 0 {
		t.Fatalf("mutator should not be called after lost lease, got %d", mut.calls)
	}
	events, _ := j.List()
	if len(events) == 0 || events[len(events)-1].Status != "lost_lease_mutation_aborted" {
		t.Fatalf("expected lost lease audit event, got %+v", events)
	}
}

func TestGovernedExecutorLostLeaseMidMutationCancelsContextMutator(t *testing.T) {
	reg := resources.NewRegistry()
	j := &memoryJournal{}
	exec := NewGovernedExecutor(j, breaker.New(5, time.Minute, time.Second), reg)
	mut := &blockingMutator{called: make(chan struct{}), release: make(chan struct{})}
	exec.RegisterMutator("ip_access_rules", mut)

	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- exec.ExecuteBatch(ctx, MutationBatch{
			ID: "batch-lost-mid",
			Operations: []MutationOperation{{
				OperationID:  "op-1",
				Type:         "create",
				ResourceType: "ip_access_rules",
			}},
		})
	}()
	select {
	case <-mut.called:
	case <-time.After(time.Second):
		t.Fatal("mutator was not called")
	}
	cancel(errors.New("lost lease: heartbeat failed"))
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected execution error after lost lease")
		}
	case <-time.After(time.Second):
		t.Fatal("executor did not stop after lost lease")
	}
	events, _ := j.List()
	found := false
	for _, event := range events {
		if event.Status == "lost_lease_mutation_aborted" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected lost lease audit event, got %+v", events)
	}
}

func TestGovernedExecutorStaleFencingTokenRefusesMutation(t *testing.T) {
	leases := fakeLeaseLookup{scopeID: "scope-a", active: &rmodels.Lease{
		ID:           "lease-current",
		Owner:        "worker-a",
		Action:       "reconcile",
		EpochID:      "epoch-a",
		FencingToken: 7,
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		CreatedAt:    time.Now().UTC(),
	}}

	j := &memoryJournal{}
	exec := NewGovernedExecutor(j, breaker.New(5, time.Minute, time.Second), resources.NewRegistry())
	mut := &spyMutator{}
	exec.RegisterMutator("ip_access_rules", mut)
	exec.SetFencingValidator(NewLeaseStoreFencingValidator(leases))
	recorder := &sinks.RecorderSink{}
	exec.SetTelemetrySink(recorder)

	err := exec.ExecuteBatch(context.Background(), MutationBatch{
		ID: "batch-stale-fencing",
		Operations: []MutationOperation{{
			OperationID:  "op-stale",
			ScopeID:      "scope-a",
			Type:         "create",
			ResourceType: "ip_access_rules",
			LeaseID:      "lease-old",
			FencingToken: 6,
			LeaseAction:  "reconcile",
		}},
	})
	if err == nil {
		t.Fatal("expected stale fencing error")
	}
	if mut.calls != 0 {
		t.Fatalf("mutator should not be called for stale token, got %d", mut.calls)
	}
	events, _ := j.List()
	if len(events) == 0 || events[len(events)-1].Status != "stale_fencing_token_mutation_refused" {
		t.Fatalf("expected stale fencing audit event, got %+v", events)
	}
	if len(recorder.Events) != 1 || recorder.Events[0].SuppressionReason != "stale_fencing_token" {
		t.Fatalf("expected stale fencing telemetry, got %+v", recorder.Events)
	}
}

func TestGovernedExecutorValidFencingTokenAllowsMutation(t *testing.T) {
	leases := fakeLeaseLookup{scopeID: "scope-a", active: &rmodels.Lease{
		ID:           "lease-current",
		Owner:        "worker-a",
		Action:       "reconcile",
		EpochID:      "epoch-a",
		FencingToken: 7,
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		CreatedAt:    time.Now().UTC(),
	}}

	exec := NewGovernedExecutor(&memoryJournal{}, breaker.New(5, time.Minute, time.Second), resources.NewRegistry())
	mut := &spyMutator{}
	exec.RegisterMutator("ip_access_rules", mut)
	exec.SetFencingValidator(NewLeaseStoreFencingValidator(leases))

	if err := exec.ExecuteBatch(context.Background(), MutationBatch{
		ID: "batch-valid-fencing",
		Operations: []MutationOperation{{
			OperationID:  "op-valid",
			ScopeID:      "scope-a",
			Type:         "create",
			ResourceType: "ip_access_rules",
			LeaseID:      "lease-current",
			FencingToken: 7,
			LeaseAction:  "reconcile",
		}},
	}); err != nil {
		t.Fatalf("expected valid fencing token to allow mutation: %v", err)
	}
	if mut.calls != 1 {
		t.Fatalf("expected one mutator call, got %d", mut.calls)
	}
}

func TestGovernedExecutorStrictFencingRequiresMetadata(t *testing.T) {
	leases := fakeLeaseLookup{scopeID: "scope-a", active: &rmodels.Lease{
		ID:           "lease-current",
		Owner:        "worker-a",
		Action:       "reconcile",
		EpochID:      "epoch-a",
		FencingToken: 7,
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		CreatedAt:    time.Now().UTC(),
	}}

	j := &memoryJournal{}
	exec := NewGovernedExecutor(j, breaker.New(5, time.Minute, time.Second), resources.NewRegistry())
	mut := &spyMutator{}
	exec.RegisterMutator("ip_access_rules", mut)
	exec.SetFencingValidator(NewLeaseStoreFencingValidator(leases).RequireFencing(true))

	err := exec.ExecuteBatch(context.Background(), MutationBatch{
		ID: "batch-missing-fencing",
		Operations: []MutationOperation{{
			OperationID:  "op-1",
			ScopeID:      "scope-a",
			Type:         "create",
			ResourceType: "ip_access_rules",
		}},
	})
	if err == nil {
		t.Fatal("expected missing fencing metadata error")
	}
	if mut.calls != 0 {
		t.Fatalf("mutator should not be called when fencing metadata is missing, got %d", mut.calls)
	}
}

func TestGovernedExecutorConcurrentLeaderRaceStopsFollowingMutations(t *testing.T) {
	lookup := &rotatingLeaseLookup{
		scopeID: "scope-a",
		leases: []*rmodels.Lease{
			{
				ID:           "lease-current",
				Owner:        "worker-a",
				Action:       "reconcile",
				EpochID:      "epoch-a",
				FencingToken: 7,
				ExpiresAt:    time.Now().UTC().Add(time.Hour),
				CreatedAt:    time.Now().UTC(),
			},
			{
				ID:           "lease-new-leader",
				Owner:        "worker-b",
				Action:       "reconcile",
				EpochID:      "epoch-b",
				FencingToken: 8,
				ExpiresAt:    time.Now().UTC().Add(time.Hour),
				CreatedAt:    time.Now().UTC(),
			},
		},
	}

	j := &memoryJournal{}
	exec := NewGovernedExecutor(j, breaker.New(5, time.Minute, time.Second), resources.NewRegistry())
	mut := &spyMutator{}
	exec.RegisterMutator("ip_access_rules", mut)
	exec.SetFencingValidator(NewLeaseStoreFencingValidator(lookup).RequireFencing(true))

	err := exec.ExecuteBatch(context.Background(), MutationBatch{
		ID: "batch-leader-race",
		Operations: []MutationOperation{
			{
				OperationID:  "op-1",
				ScopeID:      "scope-a",
				Type:         "create",
				ResourceType: "ip_access_rules",
				LeaseID:      "lease-current",
				FencingToken: 7,
				LeaseAction:  "reconcile",
			},
			{
				OperationID:  "op-2",
				ScopeID:      "scope-a",
				Type:         "create",
				ResourceType: "ip_access_rules",
				LeaseID:      "lease-current",
				FencingToken: 7,
				LeaseAction:  "reconcile",
			},
		},
	})
	if err == nil {
		t.Fatal("expected stale fencing error on second operation")
	}
	if mut.calls != 1 {
		t.Fatalf("expected exactly one mutation before leader change refusal, got %d", mut.calls)
	}
}

var _ journal.JournalStore = (*memoryJournal)(nil)
var _ sinks.Sink = (*sinks.RecorderSink)(nil)
var _ = tmevents.SecurityEvent{}
