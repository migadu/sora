package relayqueue

import (
	"container/heap"
	"sync"
	"time"
)

// pendingResyncInterval bounds how long the in-memory index may lag the pending
// directory. Only changes made by another process arrive this late - a
// `sora-admin relay requeue` while the server is running - because every in-process
// path that puts a file into pending/ updates the index directly.
const pendingResyncInterval = 1 * time.Minute

// pendingIndex is the in-memory view of the pending directory: message ID to the time
// the message becomes due. The directory remains the source of truth; this exists so
// that picking the next message costs O(log n) in memory instead of a fresh listing
// plus a JSON parse of the whole backlog. That scan used to run under the same mutex
// the LMTP enqueue path takes, which made relay backlog size a brake on accepting
// inbound mail - worst of all with the relay circuit breaker open, when nothing drains.
//
// Its mutex is a leaf: it is never held across disk I/O and takes no other lock.
type pendingIndex struct {
	mu       sync.Mutex
	queue    pendingHeap          // ordered by retry time, earliest first
	retryAt  map[string]time.Time // membership; heap entries that disagree are stale
	syncedAt time.Time            // last rebuild from the directory; zero means never
}

func newPendingIndex() *pendingIndex {
	return &pendingIndex{retryAt: make(map[string]time.Time)}
}

// add records a message that is now sitting in the pending directory.
func (p *pendingIndex) add(id string, retryAt time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, ok := p.retryAt[id]; ok && existing.Equal(retryAt) {
		return
	}
	p.retryAt[id] = retryAt
	heap.Push(&p.queue, pendingEntry{id: id, retryAt: retryAt})
}

// takeDue removes and returns the message that has been due the longest, if any.
func (p *pendingIndex) takeDue(now time.Time) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for p.queue.Len() > 0 {
		next := p.queue[0]
		if at, ok := p.retryAt[next.id]; !ok || !at.Equal(next.retryAt) {
			heap.Pop(&p.queue) // superseded by a later add, or already taken
			continue
		}
		if next.retryAt.After(now) {
			return "", false
		}
		heap.Pop(&p.queue)
		delete(p.retryAt, next.id)
		return next.id, true
	}
	return "", false
}

// stale reports whether the index should be rebuilt from the directory.
func (p *pendingIndex) stale(now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return now.Sub(p.syncedAt) >= pendingResyncInterval
}

// merge folds a directory listing into the index. It only adds: an ID the scan did not
// see may simply have been enqueued while the scan was running, and an ID whose files
// have gone is dropped by the acquire path when it fails to claim it.
func (p *pendingIndex) merge(onDisk map[string]time.Time, syncedAt time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for id, at := range onDisk {
		if _, ok := p.retryAt[id]; ok {
			continue
		}
		p.retryAt[id] = at
		heap.Push(&p.queue, pendingEntry{id: id, retryAt: at})
	}
	p.syncedAt = syncedAt
}

// invalidate forces the next acquire to rebuild the index from the directory.
func (p *pendingIndex) invalidate() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.syncedAt = time.Time{}
}

// pendingEntry is one message in the index.
type pendingEntry struct {
	id      string
	retryAt time.Time
}

// pendingHeap orders pending messages by retry time, earliest first.
type pendingHeap []pendingEntry

func (h pendingHeap) Len() int           { return len(h) }
func (h pendingHeap) Less(i, j int) bool { return h[i].retryAt.Before(h[j].retryAt) }
func (h pendingHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *pendingHeap) Push(x any) { *h = append(*h, x.(pendingEntry)) }

func (h *pendingHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}
