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

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

const icewarpCap = "X-ICEWARP-SERVER"

// setupIMAPProxyWithAdditionalCaps starts an IMAP proxy advertising the given
// extra capability tokens (config: additional_caps) in its pre-auth greeting and
// CAPABILITY response.
func setupIMAPProxyWithAdditionalCaps(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, additionalCaps []string) *common.TestServer {
	t.Helper()

	opts := imapproxy.ServerOptions{
		Name:               "test-proxy-additional-caps",
		Addr:               proxyAddr,
		RemoteAddrs:        backendAddrs,
		RemotePort:         143,
		MasterSASLUsername: "proxyuser",
		MasterSASLPassword: "proxypass",
		RemoteUseIDCommand: true,
		ConnectTimeout:     10 * time.Second,
		AuthIdleTimeout:    30 * time.Minute,
		AuthRateLimit:      server.AuthRateLimiterConfig{Enabled: false},
		TrustedProxies:     []string{"127.0.0.0/8", "::1/128"},
		AdditionalCaps:     additionalCaps,
	}

	proxy, err := imapproxy.New(context.Background(), rdb, "test-proxy-additional-caps", opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP proxy error: %w", err)
		}
	}()
	time.Sleep(200 * time.Millisecond)

	testServer := &common.TestServer{Address: proxyAddr, Server: proxy, ResilientDB: rdb}
	testServer.SetCleanup(func() {
		proxy.Stop()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("IMAP proxy error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
		}
	})
	return testServer
}

// proxyGreetingAndCapability dials the proxy raw, returns the untagged greeting
// line and the untagged response to a pre-auth CAPABILITY command.
func proxyGreetingAndCapability(t *testing.T, addr string) (greeting, capability string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	line, _, err := r.ReadLine()
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	greeting = string(line)

	if _, err := fmt.Fprintf(conn, "A1 CAPABILITY\r\n"); err != nil {
		t.Fatalf("Failed to send CAPABILITY: %v", err)
	}
	for {
		l, _, err := r.ReadLine()
		if err != nil {
			t.Fatalf("Failed to read CAPABILITY response: %v", err)
		}
		s := string(l)
		if strings.HasPrefix(s, "* CAPABILITY") {
			capability = s
		}
		if strings.HasPrefix(s, "A1 ") {
			break
		}
	}
	return greeting, capability
}

// TestIMAPProxy_AdditionalCaps verifies a configured additional capability token
// appears in the proxy's pre-auth greeting and CAPABILITY response.
func TestIMAPProxy_AdditionalCaps(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, _ := common.SetupIMAPServerWithMaster(t)
	defer backendServer.Close()

	proxyAddr := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithAdditionalCaps(t, backendServer.ResilientDB, proxyAddr, []string{backendServer.Address}, []string{icewarpCap})
	defer proxy.Close()

	greeting, capability := proxyGreetingAndCapability(t, proxyAddr)
	t.Logf("Greeting: %s", greeting)
	t.Logf("CAPABILITY: %s", capability)

	if !strings.Contains(greeting, icewarpCap) {
		t.Errorf("proxy greeting missing %q: %s", icewarpCap, greeting)
	}
	if !strings.Contains(capability, icewarpCap) {
		t.Errorf("proxy CAPABILITY missing %q: %s", icewarpCap, capability)
	}
	// Augment, not replace: a standard token is still present.
	if !strings.Contains(capability, "IMAP4rev1") {
		t.Errorf("proxy CAPABILITY dropped IMAP4rev1: %s", capability)
	}

	t.Logf("SUCCESS: %q advertised in proxy greeting and pre-auth CAPABILITY", icewarpCap)
}

// TestIMAPProxy_AdditionalCaps_Absent verifies the token is NOT advertised when
// additional_caps is unset (negative control).
func TestIMAPProxy_AdditionalCaps_Absent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, _ := common.SetupIMAPServerWithMaster(t)
	defer backendServer.Close()

	proxyAddr := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithAdditionalCaps(t, backendServer.ResilientDB, proxyAddr, []string{backendServer.Address}, nil)
	defer proxy.Close()

	greeting, capability := proxyGreetingAndCapability(t, proxyAddr)
	if strings.Contains(greeting, icewarpCap) {
		t.Errorf("proxy greeting unexpectedly advertised %q: %s", icewarpCap, greeting)
	}
	if strings.Contains(capability, icewarpCap) {
		t.Errorf("proxy CAPABILITY unexpectedly advertised %q: %s", icewarpCap, capability)
	}
}
