package fp_memory

import (
	"testing"
	"time"
)

func TestPenaltyDecaysOverTime(t *testing.T) {
	store := New(24 * time.Hour)
	now := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
	store.Remember("ip:1.2.3.4", "appsec", "appsec", true, now)

	initial := store.Penalty("ip:1.2.3.4", now)
	later := store.Penalty("ip:1.2.3.4", now.Add(48*time.Hour))
	if later >= initial {
		t.Fatalf("expected penalty decay, initial=%f later=%f", initial, later)
	}
}
