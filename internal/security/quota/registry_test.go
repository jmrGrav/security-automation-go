package quota

import "testing"

func TestRegistryRecordsLatestObservation(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	first := Observation{Provider: "cloudflare", LimitKnown: true, Limit: 100, RemainingKnown: true, Remaining: 20, PercentKnown: true, RemainingPercent: 20}
	second := Observation{Provider: "cloudflare", LimitKnown: true, Limit: 100, RemainingKnown: true, Remaining: 4, PercentKnown: true, RemainingPercent: 4}

	if got := r.Record(first); got.Previous != Unknown || got.Current != Normal {
		t.Fatalf("unexpected transition for first record: %+v", got)
	}
	if got := r.Record(second); got.Previous != Normal || got.Current != Throttled {
		t.Fatalf("unexpected transition for second record: %+v", got)
	}

	obs, ok := r.Get("cloudflare")
	if !ok {
		t.Fatal("expected observation")
	}
	if obs.State != Throttled || obs.Remaining != 4 {
		t.Fatalf("unexpected stored observation: %+v", obs)
	}

	snapshot := r.Snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("expected one snapshot entry, got %d", len(snapshot))
	}
}
