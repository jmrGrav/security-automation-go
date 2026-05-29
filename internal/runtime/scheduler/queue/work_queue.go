package queue

import (
	"container/heap"
	"sync"

	"github.com/jm/security-automation-go/internal/runtime/models"
)

// WorkQueue is a thread-safe priority queue for reconciliation tasks.
type WorkQueue struct {
	mu    sync.Mutex
	items priorityHeap
}

func New() *WorkQueue {
	q := &WorkQueue{}
	heap.Init(&q.items)
	return q
}

func (q *WorkQueue) Push(item models.WorkItem) {
	q.mu.Lock()
	defer q.mu.Unlock()
	heap.Push(&q.items, item)
}

func (q *WorkQueue) Pop() (models.WorkItem, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.items.Len() == 0 {
		return models.WorkItem{}, false
	}
	item := heap.Pop(&q.items).(models.WorkItem)
	return item, true
}

func (q *WorkQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.items.Len()
}

// Internal heap implementation
type priorityHeap []models.WorkItem

func (h priorityHeap) Len() int           { return len(h) }
func (h priorityHeap) Less(i, j int) bool { return h[i].Priority > h[j].Priority } // Higher priority first
func (h priorityHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *priorityHeap) Push(x interface{}) {
	*h = append(*h, x.(models.WorkItem))
}

func (h *priorityHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[0 : n-1]
	return item
}
