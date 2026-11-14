package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/health"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/adminapi"
)

// limitsTestNode is one cluster node running an IMAP proxy started the way main
// starts it, from the node's own dependencies.
type limitsTestNode struct {
	cluster *cluster.Manager
	addr    string
}

// startLimitsTestCluster starts two cluster members on loopback, each running an
// IMAP proxy (configured by cfgA and cfgB), and waits until both see each other.
func startLimitsTestCluster(t *testing.T, cfgA, cfgB config.ServerConfig) (a, b limitsTestNode) {
	t.Helper()

	nodeA := startLimitsTestMember(t, "limits-node-a", nil)
	nodeB := startLimitsTestMember(t, "limits-node-b", []string{limitsTestGossipAddr(t, nodeA)})

	deadline := time.Now().Add(10 * time.Second)
	for nodeA.GetMemberCount() < 2 || nodeB.GetMemberCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("cluster did not form: A=%d B=%d members", nodeA.GetMemberCount(), nodeB.GetMemberCount())
		}
		time.Sleep(20 * time.Millisecond)
	}

	return limitsTestNode{cluster: nodeA, addr: startLimitsTestProxy(t, nodeA, cfgA)},
		limitsTestNode{cluster: nodeB, addr: startLimitsTestProxy(t, nodeB, cfgB)}
}

func startLimitsTestMember(t *testing.T, nodeID string, peers []string) *cluster.Manager {
	t.Helper()
	mgr, err := cluster.New(config.ClusterConfig{
		Enabled:   true,
		Addr:      "127.0.0.1:0",
		NodeID:    nodeID,
		Peers:     peers,
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
	})
	if err != nil {
		t.Fatalf("start cluster node %s: %v", nodeID, err)
	}
	t.Cleanup(func() { _ = mgr.Shutdown() })
	return mgr
}

func limitsTestGossipAddr(t *testing.T, mgr *cluster.Manager) string {
	t.Helper()
	for _, m := range mgr.GetMembers() {
		if m.Name == mgr.GetNodeID() {
			return net.JoinHostPort(m.Addr, fmt.Sprint(m.Port))
		}
	}
	t.Fatalf("node %s is not among its own members", mgr.GetNodeID())
	return ""
}

// startLimitsTestProxy runs startDynamicIMAPProxyServer for one node. The node's
// configuration is the server default with [cluster] enabled and nothing else
// said about rate_limit_sync, which is how most cluster configs read.
func startLimitsTestProxy(t *testing.T, mgr *cluster.Manager, serverCfg config.ServerConfig) string {
	t.Helper()

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick a port: %v", err)
	}
	addr := probe.Addr().String()
	probe.Close()

	cfg := config.NewDefaultConfig()
	cfg.Cluster.Enabled = true
	cfg.Cluster.NodeID = mgr.GetNodeID()
	cfg.Servers.TrustedNetworks = nil

	serverCfg.Addr = addr
	deps := &serverDependencies{
		clusterManager:     mgr,
		config:             cfg,
		hostname:           "mail.example.com",
		serverManager:      &serverManager{},
		connectionTrackers: make(map[string]*server.ConnectionTracker),
		proxyServers:       make(map[string]adminapi.ProxyServer),
		healthIntegration:  health.NewHealthIntegration(nil),
	}

	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go startDynamicIMAPProxyServer(ctx, deps, serverCfg, errChan)
	t.Cleanup(func() {
		cancel()
		deps.serverManager.Wait()
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-errChan:
			t.Fatalf("IMAP proxy on %s: %v", mgr.GetNodeID(), err)
		default:
		}
		if conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			conn.Close()
			// The probe was a connection: wait for its release to reach the peer.
			time.Sleep(500 * time.Millisecond)
			return addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("IMAP proxy on %s did not start listening on %s", mgr.GetNodeID(), addr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func limitsTestProxyConfig() config.ServerConfig {
	healthChecks := false
	return config.ServerConfig{
		Type: "imap_proxy",
		Name: "imap-proxy",
		// Never dialled: every login in these tests fails before a backend is chosen.
		RemoteAddrs:        []string{"127.0.0.1:1"},
		RemoteHealthChecks: &healthChecks,
	}
}

// readLine reads one response line, or returns "" if the proxy closed the connection.
func readLine(t *testing.T, conn net.Conn, r *bufio.Reader) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimRight(line, "\r\n")
}

// TestClusterProxyPerIPLimitIsClusterWide: with max_connections_per_ip = 1, a client
// address holding a connection on one node must be refused by the other.
func TestClusterProxyPerIPLimitIsClusterWide(t *testing.T) {
	serverCfg := limitsTestProxyConfig()
	serverCfg.MaxConnectionsPerIP = 1
	a, b := startLimitsTestCluster(t, serverCfg, serverCfg)

	connA, err := net.Dial("tcp", a.addr)
	if err != nil {
		t.Fatalf("dial node A: %v", err)
	}
	defer connA.Close()
	if greeting := readLine(t, connA, bufio.NewReader(connA)); !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("node A greeting: %q", greeting)
	}

	// The connection on node A reaches node B by gossip.
	deadline := time.Now().Add(5 * time.Second)
	for {
		connB, err := net.Dial("tcp", b.addr)
		if err != nil {
			t.Fatalf("dial node B: %v", err)
		}
		greeting := readLine(t, connB, bufio.NewReader(connB))
		connB.Close()
		if greeting == "" {
			return // refused: the limit is cluster-wide
		}
		if time.Now().After(deadline) {
			t.Fatalf("node B accepted a second connection from 127.0.0.1 although max_connections_per_ip = 1 is held on node A (greeting %q)", greeting)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestClusterProxyAuthBlockIsClusterWide: an address blocked for failed logins on
// one node must be refused by the other. A refused login never reaches the
// lookup API, which is how the test tells a refusal from an ordinary failure:
// both answer NO on the wire. Each login names a different user so that the
// proxy's negative lookup cache cannot stand in for the API.
func TestClusterProxyAuthBlockIsClusterWide(t *testing.T) {
	var looked sync.Map
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		looked.Store(r.URL.Query().Get("email"), true)
		http.NotFound(w, r) // no such user: every login fails
	}))
	defer lookup.Close()

	rateLimit := server.DefaultAuthRateLimiterConfig()
	rateLimit.Enabled = true
	rateLimit.MaxAttemptsPerIPUsername = 0
	rateLimit.MaxAttemptsPerIP = 2
	rateLimit.DelayStartThreshold = 100

	cfgA := limitsTestProxyConfig()
	cfgA.AuthRateLimit = &rateLimit
	cfgA.RemoteLookup = &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email"}

	// Node B's own threshold is out of reach, so the logins this test makes there
	// while waiting for gossip cannot block the address locally: only node A's
	// block can.
	rateLimitB := rateLimit
	rateLimitB.MaxAttemptsPerIP = 1000
	cfgB := cfgA
	cfgB.AuthRateLimit = &rateLimitB

	a, b := startLimitsTestCluster(t, cfgA, cfgB)

	// login fails a LOGIN for user and reports whether the proxy asked the lookup
	// API about it, that is, whether it let the attempt through.
	attempt := 0
	login := func(addr string) (user string, reachedLookup bool) {
		t.Helper()
		attempt++
		user = fmt.Sprintf("user%d@example.com", attempt)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %s: %v", addr, err)
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		if greeting := readLine(t, conn, r); !strings.HasPrefix(greeting, "* OK") {
			t.Fatalf("greeting from %s: %q", addr, greeting)
		}
		fmt.Fprintf(conn, "t%d LOGIN %s wrong-password\r\n", attempt, user)
		for {
			line := readLine(t, conn, r)
			if line == "" || strings.HasPrefix(line, fmt.Sprintf("t%d ", attempt)) {
				break
			}
		}
		_, reachedLookup = looked.Load(user)
		return user, reachedLookup
	}

	for range rateLimit.MaxAttemptsPerIP {
		if user, reached := login(a.addr); !reached {
			t.Fatalf("node A refused the login of %s before the address had failed", user)
		}
	}
	if user, reached := login(a.addr); reached {
		t.Fatalf("node A let %s through after %d failures from the address", user, rateLimit.MaxAttemptsPerIP)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		user, reached := login(b.addr)
		if !reached {
			return // node B refuses the address node A blocked
		}
		if time.Now().After(deadline) {
			t.Fatalf("node B still lets the address node A blocked log in (last attempt %s)", user)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
