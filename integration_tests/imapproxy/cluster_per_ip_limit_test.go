//go:build integration

package imapproxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

// TestIMAPProxyClusterWidePerIPLimit tests that per-IP connection limits are enforced cluster-wide
// This verifies that with max_connections_per_ip=2, an IP can only make 2 connections total across
// all nodes in the cluster, not 2 per node.
func TestIMAPProxyClusterWidePerIPLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, _ := common.SetupIMAPServer(t)
	defer backendServer.Close()

	// Create two cluster managers (simulating 2-node cluster)
	clusterCfg1 := config.ClusterConfig{
		Enabled:   true,
		NodeID:    "node1",
		Addr:      "127.0.0.1:17946", // Different port from default 7946
		Peers:     []string{"127.0.0.1:17947"},
		SecretKey: "dGVzdC1zZWNyZXQta2V5LTEyMzQ1Njc4OTAxMjM0NTY=", // base64 encoded 32-byte key
	}
	clusterCfg2 := config.ClusterConfig{
		Enabled:   true,
		NodeID:    "node2",
		Addr:      "127.0.0.1:17947",
		Peers:     []string{"127.0.0.1:17946"},
		SecretKey: "dGVzdC1zZWNyZXQta2V5LTEyMzQ1Njc4OTAxMjM0NTY=",
	}

	clusterMgr1, err := cluster.New(clusterCfg1)
	if err != nil {
		t.Fatalf("Failed to create cluster manager 1: %v", err)
	}
	defer clusterMgr1.Shutdown()

	clusterMgr2, err := cluster.New(clusterCfg2)
	if err != nil {
		t.Fatalf("Failed to create cluster manager 2: %v", err)
	}
	defer clusterMgr2.Shutdown()

	// Wait for cluster to form
	time.Sleep(2 * time.Second)

	// Set up two IMAP proxies with cluster-wide per-IP limits
	proxyAddr1 := common.GetRandomAddress(t)
	proxyAddr2 := common.GetRandomAddress(t)

	proxy1 := setupIMAPProxyWithCluster(t, backendServer.ResilientDB, proxyAddr1,
		[]string{backendServer.Address}, clusterMgr1, 100, 2, []string{}) // maxTotal=100, maxPerIP=2 cluster-wide
	defer proxy1.Close()

	proxy2 := setupIMAPProxyWithCluster(t, backendServer.ResilientDB, proxyAddr2,
		[]string{backendServer.Address}, clusterMgr2, 100, 2, []string{})
	defer proxy2.Close()

	t.Log("=== Testing Cluster-Wide Per-IP Connection Limiting ===")
	t.Logf("Node 1: %s, Node 2: %s", proxyAddr1, proxyAddr2)
	t.Log("Config: maxTotal=100, maxPerIP=2 (cluster-wide), trustedNetworks=[]")
	t.Log("Expected: IP can make max 2 connections TOTAL across both nodes")

	// Test 1: Single IP across two nodes should be limited to 2 total
	t.Log("\n--- Test 1: Cluster-wide per-IP limit enforcement ---")

	// Connect to node 1
	conn1, err := net.Dial("tcp", proxyAddr1)
	if err != nil {
		t.Fatalf("First connection to node1 should succeed: %v", err)
	}
	defer conn1.Close()
	t.Log("✓ Connection 1 to node1 succeeded")
	time.Sleep(200 * time.Millisecond) // Allow gossip to propagate

	// Connect to node 2 (same IP, different node)
	conn2, err := net.Dial("tcp", proxyAddr2)
	if err != nil {
		t.Fatalf("Second connection to node2 should succeed: %v", err)
	}
	defer conn2.Close()
	t.Log("✓ Connection 2 to node2 succeeded")
	time.Sleep(200 * time.Millisecond) // Allow gossip to propagate

	// Third connection to either node should be rejected (cluster-wide limit reached)
	t.Log("Attempting third connection to node1 (should be rejected - cluster limit)...")
	conn3, err := net.Dial("tcp", proxyAddr1)
	if err != nil {
		t.Logf("✓ Third connection correctly rejected during dial: %v", err)
	} else {
		defer conn3.Close()
		// Connection accepted at TCP level but should be closed by limiter
		time.Sleep(200 * time.Millisecond)

		conn3.SetReadDeadline(time.Now().Add(1 * time.Second))
		buffer := make([]byte, 1024)
		n, err := conn3.Read(buffer)
		if err != nil || n == 0 {
			t.Log("✓ Third connection was closed by cluster-wide limiter")
		} else {
			t.Errorf("❌ Third connection should have been rejected (cluster maxPerIP=2)")
		}
	}

	// Test 2: Verify counter decrements work cluster-wide
	t.Log("\n--- Test 2: Cluster-wide counter decrement ---")
	conn1.Close()
	time.Sleep(300 * time.Millisecond) // Allow gossip to propagate decrement

	// Should now be able to connect again (1 connection freed)
	conn4, err := net.Dial("tcp", proxyAddr1)
	if err != nil {
		t.Errorf("Fourth connection should succeed after closing first: %v", err)
	} else {
		defer conn4.Close()
		t.Log("✓ Connection succeeded after closing one (cluster counter decremented)")
	}

	t.Log("\n=== Cluster-wide per-IP limiting test completed ===")
}

// setupIMAPProxyWithCluster creates an IMAP proxy with cluster-wide per-IP limiting
func setupIMAPProxyWithCluster(t *testing.T, rdb *resilient.ResilientDatabase,
	proxyAddr string, backendAddrs []string, clusterMgr *cluster.Manager,
	maxConnections, maxConnectionsPerIP int, trustedNetworks []string) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-cluster"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := imapproxy.ServerOptions{
		Name:                   fmt.Sprintf("test-proxy-cluster-%s", proxyAddr),
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             143,
		MasterSASLUsername:     masterUsername,
		MasterSASLPassword:     masterPassword,
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: false,
		RemoteUseIDCommand:     false,
		ConnectTimeout:         5 * time.Second,
		AuthIdleTimeout:        10 * time.Minute,
		EnableAffinity:         false,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},

		// Connection limiting with cluster support
		MaxConnections:      maxConnections,
		MaxConnectionsPerIP: maxConnectionsPerIP,
		TrustedNetworks:     trustedNetworks,
		ClusterManager:      clusterMgr, // Enable cluster-wide per-IP limiting
	}

	proxy, err := imapproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy with cluster: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil &&
			!strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP proxy error: %w", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}
}
