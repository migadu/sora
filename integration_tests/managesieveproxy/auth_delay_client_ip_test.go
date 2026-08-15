//go:build integration

package managesieveproxy_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieveproxy"
)

// setupManageSieveProxyWithIncomingPROXYAndRateLimiting creates a ManageSieve proxy
// that accepts PROXY protocol headers from loopback and has auth rate limiting on.
func setupManageSieveProxyWithIncomingPROXYAndRateLimiting(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, rateLimitConfig server.AuthRateLimiterConfig) *common.TestServer {
	t.Helper()

	opts := managesieveproxy.ServerOptions{
		Name:               "test-managesieve-proxy-delay-client-ip",
		Addr:               proxyAddr,
		RemoteAddrs:        backendAddrs,
		RemotePort:         4190,
		MasterSASLUsername: proxyMasterSASLUsername,
		MasterSASLPassword: proxyMasterSASLPassword,
		InsecureAuth:       true,
		ConnectTimeout:     10 * time.Second,
		AuthIdleTimeout:    30 * time.Minute,
		CommandTimeout:     5 * time.Minute,
		AuthRateLimit:      rateLimitConfig,
		// TrustedNetworks gates the PROXY header (loopback is the load balancer here).
		// TrustedProxies is the rate-limiter EXEMPTION list and is deliberately left
		// empty so the forwarded client IP is still rate limited.
		TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"},
		ProxyProtocol:        true,
		ProxyProtocolTimeout: "5s",
	}

	proxy, err := managesieveproxy.New(context.Background(), rdb, "test-managesieve-proxy-delay-client-ip", opts)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("ManageSieve proxy error: %v", err)
		}
	}()
	time.Sleep(200 * time.Millisecond)

	t.Cleanup(func() { proxy.Stop() })

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}
}

// TestManageSieveProxy_AuthDelay_UsesRealClientIP proves the progressive
// authentication delay is keyed on the real client IP from the PROXY header, not on
// the upstream load balancer's address (see the IMAP proxy counterpart for the full
// rationale). The assertion is on the sora_auth_delay_completed_total counter's "ip"
// label: no timing thresholds.
func TestManageSieveProxy_AuthDelay_UsesRealClientIP(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	const clientIP = "203.0.113.79" // the "real" client behind the load balancer
	const lbIP = "127.0.0.1"        // the load balancer (the socket peer)

	proxyAddr := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithIncomingPROXYAndRateLimiting(t, backendServer.ResilientDB, proxyAddr, []string{backendServer.Address}, server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 0,  // Tier 1 off: isolate the delay behaviour
		MaxAttemptsPerIP:         10, // Tier 2 on (it tracks the failures delays are based on)
		IPBlockDuration:          1 * time.Minute,
		IPWindowDuration:         5 * time.Minute,
		DelayStartThreshold:      2, // delay from the 3rd attempt on
		InitialDelay:             300 * time.Millisecond,
		MaxDelay:                 1 * time.Second,
		DelayMultiplier:          2.0,
		CleanupInterval:          1 * time.Minute,
	})
	defer proxy.Close()

	authBehindLB := func(password string) string {
		conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		header, err := server.GenerateProxyV2Header(clientIP, 54321, lbIP, conn.LocalAddr().(*net.TCPAddr).Port, "TCP4")
		if err != nil {
			t.Fatalf("generate PROXY header: %v", err)
		}
		if _, err := conn.Write(header); err != nil {
			t.Fatalf("write PROXY header: %v", err)
		}

		reader := bufio.NewReader(conn)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		// Read the capability greeting up to its terminating OK.
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read greeting: %v", err)
			}
			if strings.HasPrefix(strings.TrimSpace(line), "OK") {
				break
			}
		}

		encoded := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00" + password))
		fmt.Fprintf(conn, "AUTHENTICATE \"PLAIN\" \"%s\"\r\n", encoded)
		resp, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Sprintf("NO (connection closed: %v)", err)
		}
		return strings.TrimSpace(resp)
	}

	delaysFor := func(ip string) float64 {
		return testutil.ToFloat64(metrics.AuthDelayCompleted.WithLabelValues("MANAGESIEVE-PROXY", ip))
	}

	clientBefore := delaysFor(clientIP)
	lbBefore := delaysFor(lbIP)

	for i := 0; i < 2; i++ {
		if resp := authBehindLB(fmt.Sprintf("wrong-password-%d", i)); strings.HasPrefix(resp, "OK") {
			t.Fatalf("attempt %d: authentication should have failed, got %q", i+1, resp)
		}
	}
	if resp := authBehindLB("wrong-password-2"); strings.HasPrefix(resp, "OK") {
		t.Fatalf("attempt 3: authentication should have failed, got %q", resp)
	}

	if got := delaysFor(clientIP) - clientBefore; got < 1 {
		t.Fatalf("no progressive auth delay was applied for the real client %s (delta=%v): the delay is keyed on the load balancer address, so it never fires behind a proxy", clientIP, got)
	}
	if got := delaysFor(lbIP) - lbBefore; got != 0 {
		t.Fatalf("auth delay was attributed to the load balancer %s (delta=%v) instead of the real client", lbIP, got)
	}
	t.Logf("✓ progressive auth delay applied and attributed to the real client IP %s", clientIP)
}
