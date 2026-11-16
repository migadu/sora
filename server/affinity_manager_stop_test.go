package server

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/affinitycache"
)

// stopAffinityStore records persistence calls that overlap or follow Close.
type stopAffinityStore struct {
	delay   time.Duration // how long each write takes
	entered chan struct{} // if set, signalled when a write starts
	release chan struct{} // if set, every write waits for it to be closed

	mu       sync.Mutex
	inFlight int
	closed   bool
	misuse   []string
}

func (s *stopAffinityStore) write(op string) {
	s.mu.Lock()
	if s.closed {
		s.misuse = append(s.misuse, op+" after Close")
	}
	s.inFlight++
	s.mu.Unlock()

	if s.entered != nil {
		s.entered <- struct{}{}
	}
	if s.release != nil {
		<-s.release
	}
	time.Sleep(s.delay)

	s.mu.Lock()
	s.inFlight--
	s.mu.Unlock()
}

func (s *stopAffinityStore) LoadAll(ctx context.Context) ([]affinitycache.AffinityEntry, error) {
	return nil, nil
}

func (s *stopAffinityStore) Set(ctx context.Context, entry affinitycache.AffinityEntry) error {
	s.write("Set")
	return nil
}

func (s *stopAffinityStore) Delete(ctx context.Context, username, protocol string) error {
	s.write("Delete")
	return nil
}

func (s *stopAffinityStore) Cleanup(ctx context.Context) (int64, error) {
	s.write("Cleanup")
	return 0, nil
}

func (s *stopAffinityStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inFlight > 0 {
		s.misuse = append(s.misuse, "Close while a write was running")
	}
	s.closed = true
	return nil
}

func (s *stopAffinityStore) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *stopAffinityStore) misuses() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.misuse...)
}

func newStopTestAffinityManager(store AffinityPersistStore) *AffinityManager {
	am := newTestAffinityManager()
	am.persistStore = store
	am.stopCleanup = make(chan struct{})
	return am
}

// Affinity changes after Stop (a proxy session still draining, an Admin API
// request) must not write to the store Stop closed.
func TestAffinityStopRefusesLaterPersistence(t *testing.T) {
	store := &stopAffinityStore{}
	am := newStopTestAffinityManager(store)
	am.Stop()

	now := time.Now()
	am.persistSetAsync("user@example.com", "imap", "192.0.2.1:143", "node-1", now, now.Add(time.Hour))
	am.persistDeleteAsync("user@example.com", "imap")
	am.cleanup()

	// A write started anyway runs in its own goroutine; give it time to arrive.
	for deadline := time.Now().Add(200 * time.Millisecond); time.Now().Before(deadline); {
		if len(store.misuses()) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if m := store.misuses(); len(m) > 0 {
		t.Fatalf("persistence reached the closed store: %v", m)
	}
}

// Stop closes the store only after the writes started before it have ended,
// including the expired-entry cleanup of the periodic cleanup cycle.
func TestAffinityStopWaitsForStartedPersistence(t *testing.T) {
	now := time.Now()
	for name, start := range map[string]func(am *AffinityManager){
		"set": func(am *AffinityManager) {
			am.persistSetAsync("user@example.com", "imap", "192.0.2.1:143", "node-1", now, now.Add(time.Hour))
		},
		"delete": func(am *AffinityManager) {
			am.persistDeleteAsync("user@example.com", "imap")
		},
		"cleanup": func(am *AffinityManager) {
			am.cleanup()
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := &stopAffinityStore{entered: make(chan struct{}, 1), release: make(chan struct{})}
			am := newStopTestAffinityManager(store)

			start(am)
			select {
			case <-store.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("the write never started")
			}

			stopped := make(chan struct{})
			go func() {
				am.Stop()
				close(stopped)
			}()

			time.Sleep(50 * time.Millisecond)
			if store.isClosed() {
				t.Error("Stop closed the store while a write was running")
			}
			close(store.release)

			select {
			case <-stopped:
			case <-time.After(5 * time.Second):
				t.Fatal("Stop did not return after the write ended")
			}
			if !store.isClosed() {
				t.Error("Stop did not close the store")
			}
			if m := store.misuses(); len(m) > 0 {
				t.Errorf("store misused: %v", m)
			}
		})
	}
}

// An affinity change racing Stop is either written before the store is closed
// or not at all. Under -race this also checks that registering the write is
// ordered with Stop's wait (sync.WaitGroup: "calls with a positive delta that
// occur when the counter is zero must happen before a Wait").
func TestAffinityPersistenceRacingStop(t *testing.T) {
	stores := make([]*stopAffinityStore, 0, 50)
	for range 50 {
		store := &stopAffinityStore{delay: time.Millisecond}
		stores = append(stores, store)
		am := newStopTestAffinityManager(store)

		now := time.Now()
		changed := make(chan struct{})
		go func() {
			defer close(changed)
			am.persistSetAsync("user@example.com", "imap", "192.0.2.1:143", "node-1", now, now.Add(time.Hour))
		}()
		time.Sleep(100 * time.Microsecond)
		am.Stop()
		<-changed
	}

	// A write that slipped past Stop runs in its own goroutine; let it finish.
	time.Sleep(50 * time.Millisecond)
	for i, store := range stores {
		if m := store.misuses(); len(m) > 0 {
			t.Errorf("iteration %d: %v", i, m)
		}
	}
}

func TestAffinityStopPreservesStartedWritesAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "affinity.db")
	store, err := affinitycache.New(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.Set(context.Background(), affinitycache.AffinityEntry{
		Username: "removed@example.com", Protocol: "imap", Backend: "old:143",
		AssignedAt: now, ExpiresAt: now.Add(time.Hour), NodeID: "node-b",
	}); err != nil {
		t.Fatal(err)
	}
	am := newStopTestAffinityManager(store)
	am.loadPersisted(context.Background())
	am.handleAffinityDelete(AffinityEvent{Username: "removed@example.com", Protocol: "imap", Timestamp: now.Add(time.Second)})
	am.handleAffinitySet(AffinityEvent{
		Username: "kept@example.com", Protocol: "imap", Backend: "kept:143",
		Timestamp: now, TTL: time.Hour, NodeID: "node-b",
	})
	am.Stop()

	// A late cluster event still updates memory, but must not reach the store
	// that Stop has closed or be present when that file is opened again.
	am.handleAffinitySet(AffinityEvent{
		Username: "late@example.com", Protocol: "imap", Backend: "late:143",
		Timestamp: now, TTL: time.Hour, NodeID: "node-b",
	})
	if backend, found := am.GetBackend("late@example.com", "imap"); !found || backend != "late:143" {
		t.Fatal("a late event must still update the in-memory map")
	}
	reopened, err := affinitycache.New(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted := newStopTestAffinityManager(reopened)
	t.Cleanup(restarted.Stop)
	restarted.loadPersisted(context.Background())
	if backend, found := restarted.GetBackend("kept@example.com", "imap"); !found || backend != "kept:143" {
		t.Fatalf("restart lost an admitted set: %q, found=%v", backend, found)
	}
	for _, user := range []string{"removed@example.com", "late@example.com"} {
		if backend, found := restarted.GetBackend(user, "imap"); found {
			t.Errorf("restart loaded %s as %q", user, backend)
		}
	}
}

func TestAffinityStopTimeoutEventuallyClosesStore(t *testing.T) {
	store := &stopAffinityStore{entered: make(chan struct{}, 1), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(store.release) })
	am := newStopTestAffinityManager(store)
	now := time.Now()
	am.persistSetAsync("user@example.com", "imap", "192.0.2.1:143", "node-1", now, now.Add(time.Hour))
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("the write never started")
	}
	stopped := make(chan struct{})
	go func() {
		am.stopPersistence(20 * time.Millisecond)
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("persistence shutdown ignored its deadline")
	}
	if store.isClosed() {
		t.Fatal("the timeout closed the store under an admitted write")
	}
	am.persistDeleteAsync("user@example.com", "imap")
	release.Do(func() { close(store.release) })
	for deadline := time.Now().Add(time.Second); !store.isClosed(); {
		if time.Now().After(deadline) {
			t.Fatal("the store remained open after pending writes finished")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-store.entered:
		t.Error("a write submitted after the timeout reached the store")
	default:
	}
	if misuse := store.misuses(); len(misuse) != 0 {
		t.Errorf("store misused after bounded shutdown: %v", misuse)
	}
}
