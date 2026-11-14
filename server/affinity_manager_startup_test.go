package server

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/affinitycache"
	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
)

// persistedBackend opens the affinity file at path as the next start of the
// node would and returns the backend it holds for user/imap.
func persistedBackend(t *testing.T, path, user string) (string, bool) {
	t.Helper()
	store, err := affinitycache.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	entries, err := store.LoadAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Username == user && e.Protocol == "imap" {
			return e.Backend, true
		}
	}
	return "", false
}

// A node receives gossip from the moment it joins the cluster, so events can be
// applied before it has loaded its affinity file. Memory and the file must end
// up as if the file had been loaded first: a delete received before the load is
// not undone by it, and a newer set is kept and written.
func TestAffinityLoadAfterGossipEvent(t *testing.T) {
	const user = "user@example.com"

	for _, tc := range []struct {
		name  string
		event func(am *AffinityManager, now time.Time)
		want  string // backend in memory and in the file, "" for none
	}{
		{
			name: "delete",
			event: func(am *AffinityManager, now time.Time) {
				am.handleAffinityDelete(AffinityEvent{Username: user, Protocol: "imap", Timestamp: now, NodeID: "node-b"})
			},
			want: "",
		},
		{
			name: "set",
			event: func(am *AffinityManager, now time.Time) {
				am.handleAffinitySet(AffinityEvent{
					Username: user, Protocol: "imap", Backend: "new:143",
					Timestamp: now, TTL: time.Hour, NodeID: "node-b",
				})
			},
			want: "new:143",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "affinity.db")
			store, err := affinitycache.New(path)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			if err := store.Set(ctx, affinitycache.AffinityEntry{
				Username: user, Protocol: "imap", Backend: "old:143",
				AssignedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), NodeID: "node-b",
			}); err != nil {
				t.Fatal(err)
			}

			am := newStopTestAffinityManager(store)
			tc.event(am, now)
			am.loadPersisted(ctx)

			if backend, _ := am.GetBackend(user, "imap"); backend != tc.want {
				t.Errorf("after the load the node routes by %q, want %q", backend, tc.want)
			}
			am.Stop() // waits for the writes, closes the file
			if backend, _ := persistedBackend(t, path, user); backend != tc.want {
				t.Errorf("the file holds %q for the next start, want %q", backend, tc.want)
			}
		})
	}
}

// loadBlockingStore is a persistent store whose LoadAll waits for the test, so
// that gossip can be delivered while the node is still reading its file.
type loadBlockingStore struct {
	rows    []affinitycache.AffinityEntry
	loading chan struct{} // closed when LoadAll starts
	release chan struct{} // LoadAll returns once it is closed
	sets    chan affinitycache.AffinityEntry

	closeOnce sync.Once
}

func (s *loadBlockingStore) LoadAll(ctx context.Context) ([]affinitycache.AffinityEntry, error) {
	close(s.loading)
	<-s.release
	return s.rows, nil
}

func (s *loadBlockingStore) Set(ctx context.Context, entry affinitycache.AffinityEntry) error {
	select {
	case s.sets <- entry:
	default:
	}
	return nil
}

func (s *loadBlockingStore) Delete(ctx context.Context, username, protocol string) error {
	return nil
}

func (s *loadBlockingStore) Cleanup(ctx context.Context) (int64, error) {
	return 0, nil
}

func (s *loadBlockingStore) Close() error {
	return nil
}

func (s *loadBlockingStore) releaseLoad() {
	s.closeOnce.Do(func() { close(s.release) })
}

func newAffinityTestCluster(t *testing.T, nodeID string, peers []string) *cluster.Manager {
	t.Helper()
	mgr, err := cluster.New(config.ClusterConfig{
		Enabled:   true,
		Addr:      "127.0.0.1:0",
		NodeID:    nodeID,
		Peers:     peers,
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=", // Base64-encoded 32-byte key
	})
	if err != nil {
		t.Fatalf("create cluster node %s: %v", nodeID, err)
	}
	t.Cleanup(func() { _ = mgr.Shutdown() })
	return mgr
}

// The startup path end to end: cluster.New has joined the node before the
// affinity manager exists, and a peer's SET that arrives while the manager
// reads its file must be applied and written to that file, not dropped and not
// left in memory only.
func TestAffinityGossipDuringStartupLoadIsPersisted(t *testing.T) {
	const user = "user@example.com"

	peer := newAffinityTestCluster(t, "affinity-peer", nil)
	members := peer.GetMembers()
	if len(members) != 1 {
		t.Fatalf("peer lists %d members, want itself only", len(members))
	}
	node := newAffinityTestCluster(t, "affinity-node", []string{net.JoinHostPort(members[0].Addr, strconv.Itoa(int(members[0].Port)))})
	deadline := time.Now().Add(10 * time.Second)
	for peer.GetMemberCount() < 2 || node.GetMemberCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("cluster did not form: peer=%d node=%d members", peer.GetMemberCount(), node.GetMemberCount())
		}
		time.Sleep(20 * time.Millisecond)
	}

	peerAffinity := NewAffinityManager(peer, true, time.Hour, time.Hour)
	t.Cleanup(peerAffinity.Stop)

	now := time.Now()
	store := &loadBlockingStore{
		rows: []affinitycache.AffinityEntry{{
			Username: user, Protocol: "imap", Backend: "old:143",
			AssignedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), NodeID: "affinity-node",
		}},
		loading: make(chan struct{}),
		release: make(chan struct{}),
		sets:    make(chan affinitycache.AffinityEntry, 1),
	}
	t.Cleanup(store.releaseLoad)

	started := make(chan *AffinityManager, 1)
	go func() {
		started <- NewAffinityManagerWithStore(context.Background(), node, true, time.Hour, time.Hour, store)
	}()
	select {
	case <-store.loading:
	case <-time.After(10 * time.Second):
		t.Fatal("the affinity manager never read its file")
	}

	peerAffinity.SetBackend(user, "new:143", "imap")
	select {
	case e := <-store.sets:
		if e.Username != user || e.Backend != "new:143" {
			t.Errorf("wrote %s -> %s, want %s -> new:143", e.Username, e.Backend, user)
		}
	case <-time.After(10 * time.Second):
		t.Error("a SET gossiped while the node read its affinity file was never written to the file")
	}

	store.releaseLoad()
	am := <-started
	t.Cleanup(am.Stop)
	if backend, _ := am.GetBackend(user, "imap"); backend != "new:143" {
		t.Errorf("after startup the node routes by %q, want the gossiped new:143", backend)
	}
}
