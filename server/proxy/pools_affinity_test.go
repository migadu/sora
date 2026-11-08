package proxy

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server"
)

// realAffinity is the cluster affinity manager the proxies use, on a loopback gossip node.
func realAffinity(t *testing.T) *server.AffinityManager {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	mgr, err := cluster.New(config.ClusterConfig{
		Enabled:   true,
		Addr:      addr,
		NodeID:    "pools-affinity-test",
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
	})
	if err != nil {
		t.Fatalf("cluster.New: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Shutdown() })
	return server.NewAffinityManager(mgr, true, time.Hour, time.Hour)
}

// A user the lookup moved from sora0 to sora1 still has an IMAP affinity into sora0 (the
// first protocol consulted across protocols) and a POP3 affinity to a sora1 backend. A new
// LMTP route must follow the POP3 entry, the user's backend in their pool, rather than
// being masked by the stale IMAP entry. The IMAP entry is left for the IMAP proxy to
// correct: what looks outside the pool here may be the same host as another node resolved
// it (another address family), and deleting it would wipe it cluster-wide.
func TestPools_StaleCrossProtocolAffinityDoesNotMaskAGoodOne(t *testing.T) {
	cm := newPoolsCM(t, testPoolSpecs()) // sora0 = 10.0.0.1-2, sora1 = 10.0.1.1-2, port 143
	aff := realAffinity(t)
	cm.SetAffinityManager(aff)

	// A user whose hash in sora1 is not the backend the POP3 affinity names, so following
	// the affinity is visible.
	var user, good string
	for i := 0; i < 100 && user == ""; i++ {
		u := fmt.Sprintf("moved%d@example.com", i)
		hashed := cm.GetBackendByConsistentHashInPool("sora1", u)
		for _, m := range []string{"10.0.1.1:143", "10.0.1.2:143"} {
			if m != hashed {
				user, good = u, m
			}
		}
	}
	if user == "" {
		t.Fatal("setup: no user hashes away from a sora1 member")
	}
	goodHost, _, _ := net.SplitHostPort(good)

	aff.SetBackend(user, "10.0.0.1:143", "imap")                    // stale: sora0
	aff.SetBackend(user, net.JoinHostPort(goodHost, "110"), "pop3") // the user's sora1 backend

	res, err := DetermineRoute(RouteParams{
		Ctx: context.Background(), Username: user, Protocol: "lmtp",
		RoutingInfo: &UserRoutingInfo{PoolName: "sora1"}, ConnManager: cm,
		EnableAffinity: true, ProxyName: "test",
	})
	if err != nil {
		t.Fatalf("DetermineRoute: %v", err)
	}
	if res.PreferredAddr != good {
		t.Fatalf("LMTP routed to %q (%s), want %q: the user's POP3 backend in sora1, masked by the stale IMAP entry", res.PreferredAddr, res.RoutingMethod, good)
	}
	if backend, ok := aff.GetBackend(user, "imap"); !ok || backend != "10.0.0.1:143" {
		t.Fatalf("another protocol's affinity was changed by an LMTP route: %q, %v", backend, ok)
	}
	if backend, ok := aff.GetBackend(user, "pop3"); !ok || backend != net.JoinHostPort(goodHost, "110") {
		t.Fatalf("the user's good POP3 affinity was touched: %q, %v", backend, ok)
	}
}
