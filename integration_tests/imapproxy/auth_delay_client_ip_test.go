//go:build integration

package imapproxy_test

import (
	"bufio"
	"context"
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
	"github.com/migadu/sora/server/imapproxy"
)

// setupIMAPProxyWithIncomingPROXYAndRateLimiting creates an IMAP proxy that accepts
// PROXY protocol headers from loopback and has authentication rate limiting enabled.
func setupIMAPProxyWithIncomingPROXYAndRateLimiting(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, rateLimitConfig server.AuthRateLimiterConfig) *common.TestServer {
	t.Helper()

	opts := imapproxy.ServerOptions{
		Name:               "test-proxy-delay-client-ip",
		Addr:               proxyAddr,
		RemoteAddrs:        backendAddrs,
		RemotePort:         143,
		MasterSASLUsername: backendMasterSASLUsername,
		MasterSASLPassword: backendMasterSASLPassword,
		ConnectTimeout:     10 * time.Second,
		AuthIdleTimeout:    30 * time.Minute,
		AuthRateLimit:      rateLimitConfig,
		// TrustedNetworks gates the PROXY header (loopback is the load balancer here).
		// TrustedProxies is the rate-limiter EXEMPTION list and is deliberately left
		// empty so the forwarded client IP is still rate limited.
		TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"},
		ProxyProtocol:        true,
		ProxyProtocolTimeout: "5s",
	}

	proxy, err := imapproxy.New(context.Background(), rdb, "test-proxy-delay-client-ip", opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP proxy error: %v", err)
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

// TestIMAPProxy_AuthDelay_UsesRealClientIP proves the progressive authentication
// delay on the socket proxy is keyed on the REAL client IP, not on the upstream load
// balancer's address.
//
// The proxy passed s.clientConn.RemoteAddr() to ApplyAuthenticationDelay while
// failures are recorded via RecordAuthAttemptWithProxy → GetConnectionIPs →
// proxyInfo.SrcIP. Behind haproxy/nginx/NLB — the deployment these proxies exist for —
// RemoteAddr() is the load balancer, which never accumulates failures, so the delay
// never fired for anyone.
//
// The assertion is on the sora_auth_delay_completed_total counter, whose "ip" label
// records exactly which address the delay was computed for: no timing thresholds.
func TestIMAPProxy_AuthDelay_UsesRealClientIP(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupIMAPServerWithMaster(t)
	defer backendServer.Close()

	const clientIP = "203.0.113.77" // the "real" client behind the load balancer
	const lbIP = "127.0.0.1"        // the load balancer (the socket peer)

	proxyAddr := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithIncomingPROXYAndRateLimiting(t, backendServer.ResilientDB, proxyAddr, []string{backendServer.Address}, server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 0,  // Tier 1 off: isolate the delay behaviour
		MaxAttemptsPerIP:         10, // Tier 2 on (it is what tracks failures for delays), threshold high enough not to block
		IPBlockDuration:          1 * time.Minute,
		IPWindowDuration:         5 * time.Minute,
		DelayStartThreshold:      2, // delay from the 3rd attempt on
		InitialDelay:             300 * time.Millisecond,
		MaxDelay:                 1 * time.Second,
		DelayMultiplier:          2.0,
		CleanupInterval:          1 * time.Minute,
	})
	defer proxy.Close()

	// One IMAP LOGIN through a PROXY-protocol header announcing clientIP.
	loginBehindLB := func(password string) string {
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
		writer := bufio.NewWriter(conn)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatalf("read greeting: %v", err)
		}

		fmt.Fprintf(writer, "a001 LOGIN %s %s\r\n", account.Email, password)
		if err := writer.Flush(); err != nil {
			t.Fatalf("write LOGIN: %v", err)
		}
		resp, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Sprintf("a001 NO (connection closed: %v)", err)
		}
		return strings.TrimSpace(resp)
	}

	delaysFor := func(ip string) float64 {
		return testutil.ToFloat64(metrics.AuthDelayCompleted.WithLabelValues("IMAP-PROXY", ip))
	}

	clientBefore := delaysFor(clientIP)
	lbBefore := delaysFor(lbIP)

	// Two failures push the real client's failure count to the delay threshold.
	for i := 0; i < 2; i++ {
		if resp := loginBehindLB(fmt.Sprintf("wrong-password-%d", i)); strings.Contains(resp, "a001 OK") {
			t.Fatalf("attempt %d: login should have failed, got %q", i+1, resp)
		}
	}

	// The third attempt must be delayed, and the delay must be attributed to the real
	// client IP carried in the PROXY header.
	if resp := loginBehindLB("wrong-password-2"); strings.Contains(resp, "a001 OK") {
		t.Fatalf("attempt 3: login should have failed, got %q", resp)
	}

	if got := delaysFor(clientIP) - clientBefore; got < 1 {
		t.Fatalf("no progressive auth delay was applied for the real client %s (delta=%v): the delay is keyed on the load balancer address, so it never fires behind a proxy", clientIP, got)
	}
	if got := delaysFor(lbIP) - lbBefore; got != 0 {
		t.Fatalf("auth delay was attributed to the load balancer %s (delta=%v) instead of the real client", lbIP, got)
	}
	t.Logf("✓ progressive auth delay applied and attributed to the real client IP %s", clientIP)
}
