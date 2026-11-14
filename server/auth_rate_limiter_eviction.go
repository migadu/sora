package server

import (
	"container/heap"
	"time"
)

// counterSlot is embedded in every failure counter of the auth rate limiter: the key the
// counter is stored under in its table, and its position in the eviction queue holding it.
type counterSlot struct {
	key   string
	index int
}

func (s *counterSlot) slot() *counterSlot { return s }

// queuedCounter is a failure counter held in an evictionQueue.
type queuedCounter interface {
	slot() *counterSlot
	evictionTime() time.Time // the queue's order, earliest first
}

// evictionQueue holds the counters of a tracking table in a binary min-heap on their
// evictionTime, so that the counter a full table gives up is at the root: found in O(1)
// and removed in O(log n). Searching the table for it cost O(n) under the table's write
// lock, on every failure that added a key to a full table (#719).
//
// The zero value is an empty queue. Callers hold the table's write lock.
type evictionQueue[T queuedCounter] []T

// Len, Less, Swap, Push and Pop implement heap.Interface; callers use the methods below.
func (q evictionQueue[T]) Len() int           { return len(q) }
func (q evictionQueue[T]) Less(i, j int) bool { return q[i].evictionTime().Before(q[j].evictionTime()) }

func (q evictionQueue[T]) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].slot().index = i
	q[j].slot().index = j
}

func (q *evictionQueue[T]) Push(x any) {
	c := x.(T)
	c.slot().index = len(*q)
	*q = append(*q, c)
}

func (q *evictionQueue[T]) Pop() any {
	old := *q
	n := len(old) - 1
	c := old[n]
	var zero T
	old[n] = zero
	*q = old[:n]
	c.slot().index = -1
	return c
}

// add queues c.
func (q *evictionQueue[T]) add(c T) { heap.Push(q, c) }

// holds reports whether q holds c.
func (q evictionQueue[T]) holds(c T) bool {
	i := c.slot().index
	return i >= 0 && i < len(q) && q[i].slot() == c.slot()
}

// remove takes c out of q, if q holds it.
func (q *evictionQueue[T]) remove(c T) {
	if q.holds(c) {
		heap.Remove(q, c.slot().index)
	}
}

// fix moves c to its place after its evictionTime changed, if q holds it.
func (q *evictionQueue[T]) fix(c T) {
	if q.holds(c) {
		heap.Fix(q, c.slot().index)
	}
}

// front returns the counter with the earliest evictionTime.
func (q evictionQueue[T]) front() (T, bool) {
	if len(q) == 0 {
		var zero T
		return zero, false
	}
	return q[0], true
}

// removeIf takes out every counter for which remove returns true, in one pass over q:
// a periodic cleanup that removes many counters does not pay O(log n) for each.
func (q *evictionQueue[T]) removeIf(remove func(T) bool) {
	kept := (*q)[:0]
	for _, c := range *q {
		if remove(c) {
			c.slot().index = -1
			continue
		}
		c.slot().index = len(kept)
		kept = append(kept, c)
	}
	clear((*q)[len(kept):])
	*q = kept
	heap.Init(q)
}
