package queue

import (
	"container/heap"
	"fmt"
	"sync"

	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

const defaultMaxItems = 1024

// WorkQueue is a thread-safe priority queue for reconciliation tasks.
type WorkQueue struct {
	mu       sync.Mutex
	items    workItemHeap
	byKey    map[string]*workItemEntry
	maxItems int
}

func New() *WorkQueue {
	return NewWithCapacity(defaultMaxItems)
}

func NewWithCapacity(maxItems int) *WorkQueue {
	if maxItems <= 0 {
		maxItems = defaultMaxItems
	}
	q := &WorkQueue{
		byKey:    make(map[string]*workItemEntry),
		maxItems: maxItems,
	}
	heap.Init(&q.items)
	return q
}

func (q *WorkQueue) Push(item models.WorkItem) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.byKey == nil {
		q.byKey = make(map[string]*workItemEntry)
	}
	key := workItemKey(item)
	if existing, ok := q.byKey[key]; ok {
		if item.Priority > existing.item.Priority {
			existing.item = item
			heap.Fix(&q.items, existing.index)
		}
		metrics.SchedulerQueueCoalescedTotal.Inc()
		metrics.SchedulerQueueDepth.Set(float64(q.items.Len()))
		return
	}

	if q.items.Len() >= q.maxItems {
		lowest := q.lowestPriorityEntry()
		if lowest == nil || item.Priority <= lowest.item.Priority {
			metrics.SchedulerQueueDroppedTotal.Inc()
			metrics.SchedulerQueueDepth.Set(float64(q.items.Len()))
			return
		}
		delete(q.byKey, lowest.key)
		lowest.key = key
		lowest.item = item
		q.byKey[key] = lowest
		heap.Fix(&q.items, lowest.index)
		metrics.SchedulerQueueDroppedTotal.Inc()
		metrics.SchedulerQueueDepth.Set(float64(q.items.Len()))
		return
	}

	entry := &workItemEntry{key: key, item: item}
	heap.Push(&q.items, entry)
	q.byKey[key] = entry
	metrics.SchedulerQueueDepth.Set(float64(q.items.Len()))
}

func (q *WorkQueue) Pop() (models.WorkItem, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.items.Len() == 0 {
		return models.WorkItem{}, false
	}
	entry := heap.Pop(&q.items).(*workItemEntry)
	delete(q.byKey, entry.key)
	metrics.SchedulerQueueDepth.Set(float64(q.items.Len()))
	item := entry.item
	return item, true
}

func (q *WorkQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.items.Len()
}

// Internal heap implementation
type workItemEntry struct {
	key   string
	item  models.WorkItem
	index int
}

type workItemHeap []*workItemEntry

func (h workItemHeap) Len() int { return len(h) }
func (h workItemHeap) Less(i, j int) bool {
	if h[i].item.Priority == h[j].item.Priority {
		return h[i].key < h[j].key
	}
	return h[i].item.Priority > h[j].item.Priority
}

func (h workItemHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *workItemHeap) Push(x interface{}) {
	entry := x.(*workItemEntry)
	entry.index = len(*h)
	*h = append(*h, entry)
}

func (h *workItemHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[0 : n-1]
	return item
}

func (q *WorkQueue) lowestPriorityEntry() *workItemEntry {
	if len(q.items) == 0 {
		return nil
	}
	lowest := q.items[0]
	for _, entry := range q.items[1:] {
		if entry.item.Priority < lowest.item.Priority || (entry.item.Priority == lowest.item.Priority && entry.key > lowest.key) {
			lowest = entry
		}
	}
	return lowest
}

func workItemKey(item models.WorkItem) string {
	return fmt.Sprintf("%s|%s", item.Scope.ID(), item.Type)
}
