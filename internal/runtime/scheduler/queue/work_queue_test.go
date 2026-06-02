package queue

import (
	"testing"

	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/scope"
)

func TestWorkQueuePopsHighestPriorityFirst(t *testing.T) {
	t.Parallel()

	q := New()
	q.Push(models.WorkItem{Scope: scope.RuntimeScope{ZoneID: "normal"}, Priority: models.PriorityNormal})
	q.Push(models.WorkItem{Scope: scope.RuntimeScope{ZoneID: "rollback"}, Priority: models.PriorityRollback})
	q.Push(models.WorkItem{Scope: scope.RuntimeScope{ZoneID: "high"}, Priority: models.PriorityHigh})

	first, ok := q.Pop()
	if !ok {
		t.Fatal("expected first work item")
	}
	if first.Scope.ZoneID != "rollback" {
		t.Fatalf("expected rollback priority first, got %q", first.Scope.ZoneID)
	}

	second, ok := q.Pop()
	if !ok {
		t.Fatal("expected second work item")
	}
	if second.Scope.ZoneID != "high" {
		t.Fatalf("expected high priority second, got %q", second.Scope.ZoneID)
	}
}

func TestWorkQueueCoalescesByScopeAndType(t *testing.T) {
	q := NewWithCapacity(2)

	q.Push(models.WorkItem{Scope: scope.RuntimeScope{ZoneID: "zone-a"}, Type: "reconcile", Priority: models.PriorityNormal})
	q.Push(models.WorkItem{Scope: scope.RuntimeScope{ZoneID: "zone-a"}, Type: "reconcile", Priority: models.PriorityRollback})

	if got := q.Len(); got != 1 {
		t.Fatalf("expected coalesced queue length 1, got %d", got)
	}
	item, ok := q.Pop()
	if !ok {
		t.Fatal("expected item after coalescing")
	}
	if item.Priority != models.PriorityRollback {
		t.Fatalf("expected higher priority item to win, got %v", item.Priority)
	}
}

func TestWorkQueueDropsLowPriorityWhenFull(t *testing.T) {
	q := NewWithCapacity(2)

	q.Push(models.WorkItem{Scope: scope.RuntimeScope{ZoneID: "zone-a"}, Type: "reconcile", Priority: models.PriorityHigh})
	q.Push(models.WorkItem{Scope: scope.RuntimeScope{ZoneID: "zone-b"}, Type: "reconcile", Priority: models.PriorityHigh})
	q.Push(models.WorkItem{Scope: scope.RuntimeScope{ZoneID: "zone-c"}, Type: "reconcile", Priority: models.PriorityNormal})

	if got := q.Len(); got != 2 {
		t.Fatalf("expected bounded queue length 2, got %d", got)
	}
	first, _ := q.Pop()
	second, _ := q.Pop()
	for _, item := range []models.WorkItem{first, second} {
		if item.Scope.ZoneID == "zone-c" {
			t.Fatalf("expected low-priority item to be dropped, got %+v", item)
		}
	}
}
