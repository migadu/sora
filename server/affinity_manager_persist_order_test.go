package server

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/affinitycache"
)

// orderedAffinityStore applies writes one at a time under a sync.Mutex, which
// like affinitycache.Store grants waiters no FIFO order, and keeps the
// resulting backend per key ("" when the last write was a delete).
type orderedAffinityStore struct {
	delay time.Duration // how long each write takes

	mu    sync.Mutex
	state map[string]string
}

func (s *orderedAffinityStore) LoadAll(ctx context.Context) ([]affinitycache.AffinityEntry, error) {
	return nil, nil
}

func (s *orderedAffinityStore) Set(ctx context.Context, entry affinitycache.AffinityEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	time.Sleep(s.delay)
	s.state[entry.Username+":"+entry.Protocol] = entry.Backend
	return nil
}

func (s *orderedAffinityStore) Delete(ctx context.Context, username, protocol string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	time.Sleep(s.delay)
	s.state[username+":"+protocol] = ""
	return nil
}

func (s *orderedAffinityStore) Cleanup(ctx context.Context) (int64, error) {
	return 0, nil
}

func (s *orderedAffinityStore) Close() error {
	return nil
}

func (s *orderedAffinityStore) backend(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state[key]
}

// Two changes to the same key in quick succession must reach the store in the
// order they were made: the store must end up holding what memory holds, or a
// restart loads an affinity this node had already replaced or removed.
func TestAffinityPersistenceFollowsChangeOrder(t *testing.T) {
	const users = 100
	for name, change := range map[string]func(am *AffinityManager, user string){
		"set then delete": func(am *AffinityManager, user string) {
			am.SetBackend(user, "192.0.2.1:143", "imap")
			am.DeleteBackend(user, "imap")
		},
		"delete then set": func(am *AffinityManager, user string) {
			am.DeleteBackend(user, "imap")
			am.SetBackend(user, "192.0.2.1:143", "imap")
		},
		"set then update": func(am *AffinityManager, user string) {
			am.SetBackend(user, "192.0.2.1:143", "imap")
			am.UpdateBackend(user, "192.0.2.1:143", "192.0.2.2:143", "imap")
		},
		"gossip set then delete": func(am *AffinityManager, user string) {
			now := time.Now()
			am.handleAffinitySet(AffinityEvent{
				Username: user, Protocol: "imap", Backend: "192.0.2.1:143",
				Timestamp: now, TTL: time.Hour, NodeID: "node-b",
			})
			am.handleAffinityDelete(AffinityEvent{
				Username: user, Protocol: "imap", Timestamp: now.Add(time.Millisecond), NodeID: "node-b",
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := &orderedAffinityStore{delay: time.Millisecond, state: make(map[string]string)}
			am := newTestAffinityManager()
			am.persistStore = store

			for i := range users {
				change(am, fmt.Sprintf("user%d@example.com", i))
			}
			if !am.persistWrites.Drain(10 * time.Second) {
				t.Fatal("the persistence writes did not finish")
			}

			wrong := 0
			for i := range users {
				user := fmt.Sprintf("user%d@example.com", i)
				inMemory, _ := am.GetBackend(user, "imap")
				if onDisk := store.backend(user + ":imap"); onDisk != inMemory {
					if wrong == 0 {
						t.Errorf("%s: store holds %q, memory holds %q", user, onDisk, inMemory)
					}
					wrong++
				}
			}
			if wrong > 0 {
				t.Errorf("%d of %d keys persisted out of change order", wrong, users)
			}
		})
	}
}
