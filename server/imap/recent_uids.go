package imap

import (
	"container/list"
	"sync"

	"github.com/emersion/go-imap/v2"
)

// maxRecentUIDMailboxes bounds how many mailboxes a node keeps \Recent bookkeeping for.
// Dropping an entry costs accuracy, not correctness: the next SELECT of that mailbox
// reports every message as recent, exactly as it does after a restart.
const maxRecentUIDMailboxes = 10000

// recentUIDTracker records, per mailbox, the highest UID at the last read-write SELECT
// by any session on this node, so \Recent can be computed across sessions
// (RFC 3501 §2.3.2). It keeps the most recently used maxRecentUIDMailboxes entries; a
// multi-tenant node must not accrete one entry per mailbox for the process lifetime.
// The zero value is ready for use.
type recentUIDTracker struct {
	mu    sync.Mutex
	order *list.List // front = most recently used; values are *recentUIDEntry
	items map[int64]*list.Element
}

type recentUIDEntry struct {
	mailboxID int64
	uid       imap.UID
}

func (t *recentUIDTracker) Load(mailboxID int64) (imap.UID, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	el, ok := t.items[mailboxID]
	if !ok {
		return 0, false
	}
	t.order.MoveToFront(el)
	return el.Value.(*recentUIDEntry).uid, true
}

func (t *recentUIDTracker) Store(mailboxID int64, uid imap.UID) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.items == nil {
		t.items = make(map[int64]*list.Element)
		t.order = list.New()
	}

	if el, ok := t.items[mailboxID]; ok {
		el.Value.(*recentUIDEntry).uid = uid
		t.order.MoveToFront(el)
		return
	}

	t.items[mailboxID] = t.order.PushFront(&recentUIDEntry{mailboxID: mailboxID, uid: uid})
	for t.order.Len() > maxRecentUIDMailboxes {
		oldest := t.order.Back()
		t.order.Remove(oldest)
		delete(t.items, oldest.Value.(*recentUIDEntry).mailboxID)
	}
}

// Len returns the number of mailboxes currently tracked.
func (t *recentUIDTracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.items)
}
