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

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieveproxy"
)

// setupManageSieveProxyForShutdownTest creates a simple ManageSieve proxy for graceful shutdown testing
func setupManageSieveProxyForShutdownTest(t *testing.T, rdb *common.TestServer, proxyAddr string, backendAddrs []string) *common.TestServer {
	t.Helper()

	opts := managesieveproxy.ServerOptions{
		Name:                   "test-managesieve-proxy-shutdown",
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             4190,
		MasterSASLUsername:     "master_sasl",
		MasterSASLPassword:     "master_sasl_secret",
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: false,
		InsecureAuth:           true,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		CommandTimeout:         5 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
	}

	proxy, err := managesieveproxy.New(context.Background(), rdb.ResilientDB, "test-managesieve-proxy", opts)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("ManageSieve proxy error: %w", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	testServer := &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb.ResilientDB,
	}

	testServer.SetCleanup(func() {
		proxy.Stop()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("ManageSieve proxy error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
		}
	})

	return testServer
}

// TestManageSieveProxyGracefulShutdownBeforeAuth tests that clients receive BYE message
// during graceful shutdown when they are in pre-auth state (after greeting, before AUTHENTICATE).
func TestManageSieveProxyGracefulShutdownBeforeAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup backend server
	backendServer, _ := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	// Setup proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyForShutdownTest(t, backendServer, proxyAddress, []string{backendServer.Address})
	// Don't defer proxy.Close() - we'll close it manually during test

	// Connect with raw TCP connection to capture responses
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial ManageSieve proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting (multiple lines ending with OK)
	var greetingLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting: %v", err)
		}
		greetingLines = append(greetingLines, strings.TrimSpace(line))
		if strings.HasPrefix(line, "OK") {
			break
		}
	}
	t.Logf("✓ Received greeting (%d lines)", len(greetingLines))

	// Start goroutine to read responses
	byeReceived := make(chan string, 1)
	readError := make(chan error, 1)
	go func() {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				readError <- err
				return
			}
			line = strings.TrimSpace(line)
			t.Logf("Received: %s", line)
			if strings.HasPrefix(line, "BYE") {
				byeReceived <- line
				return
			}
		}
	}()

	// Wait a moment to ensure session is established
	time.Sleep(100 * time.Millisecond)

	// Now shutdown the proxy
	t.Log("Initiating proxy shutdown...")
	proxy.Close()

	// Wait for either BYE message or error
	select {
	case byeLine := <-byeReceived:
		t.Logf("✓ Received BYE message: %s", byeLine)
		if !strings.Contains(byeLine, "TRYLATER") {
			t.Errorf("BYE message doesn't contain TRYLATER: %s", byeLine)
		}
		if !strings.Contains(byeLine, "shutting down") {
			t.Errorf("BYE message doesn't mention shutdown: %s", byeLine)
		}
	case err := <-readError:
		t.Errorf("Connection closed without BYE message: %v", err)
	case <-time.After(3 * time.Second):
		t.Error("Timeout waiting for BYE message")
	}

	t.Log("✓ Proxy shutdown completed")
}

// TestManageSieveProxyGracefulShutdownDuringAuth tests that clients receive BYE message
// during graceful shutdown when they are attempting to authenticate.
func TestManageSieveProxyGracefulShutdownDuringAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup backend server
	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	// Setup proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyForShutdownTest(t, backendServer, proxyAddress, []string{backendServer.Address})
	// Don't defer proxy.Close()

	// Connect with raw TCP connection
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial ManageSieve proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting: %v", err)
		}
		if strings.HasPrefix(line, "OK") {
			break
		}
	}
	t.Log("✓ Received greeting")

	// Start authentication
	authString := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
	encoded := base64.StdEncoding.EncodeToString([]byte(authString))

	// Send AUTHENTICATE command
	fmt.Fprintf(conn, "AUTHENTICATE \"PLAIN\" \"%s\"\r\n", encoded)

	// Shutdown almost immediately (racing with authentication)
	time.Sleep(1 * time.Millisecond)

	t.Log("Initiating proxy shutdown during authentication...")
	proxy.Close()

	// Read response - could be OK (auth succeeded), BYE (shutdown), or NO (unavailable)
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Logf("✓ Connection closed during shutdown (acceptable): %v", err)
	} else {
		response = strings.TrimSpace(response)
		t.Logf("Received response: %s", response)
		if strings.HasPrefix(response, "OK") {
			t.Log("⚠ Authentication succeeded before shutdown (timing race) - acceptable")
		} else if strings.HasPrefix(response, "BYE") {
			t.Logf("✓ Received BYE message during auth: %s", response)
			if !strings.Contains(response, "TRYLATER") {
				t.Errorf("BYE message doesn't contain TRYLATER: %s", response)
			}
		} else if strings.HasPrefix(response, "NO") && strings.Contains(response, "UNAVAILABLE") {
			t.Logf("✓ Received UNAVAILABLE response: %s", response)
		} else {
			t.Errorf("Unexpected response: %s", response)
		}
	}

	t.Log("✓ Proxy shutdown completed")
}

// TestManageSieveProxyGracefulShutdownAfterAuth tests that clients receive BYE message
// during graceful shutdown when they are already authenticated.
func TestManageSieveProxyGracefulShutdownAfterAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup backend server
	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	// Setup proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyForShutdownTest(t, backendServer, proxyAddress, []string{backendServer.Address})
	// Don't defer proxy.Close()

	// Connect with raw TCP connection
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial ManageSieve proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting: %v", err)
		}
		if strings.HasPrefix(line, "OK") {
			break
		}
	}

	// Authenticate
	authString := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
	encoded := base64.StdEncoding.EncodeToString([]byte(authString))
	fmt.Fprintf(conn, "AUTHENTICATE \"PLAIN\" \"%s\"\r\n", encoded)

	// Read authentication response
	authResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read auth response: %v", err)
	}
	if !strings.HasPrefix(authResp, "OK") {
		t.Fatalf("Authentication failed: %s", authResp)
	}
	t.Log("✓ Successfully authenticated")

	// Start goroutine to read responses
	byeReceived := make(chan string, 1)
	readError := make(chan error, 1)
	go func() {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				readError <- err
				return
			}
			line = strings.TrimSpace(line)
			t.Logf("Received: %s", line)
			if strings.HasPrefix(line, "BYE") {
				byeReceived <- line
				return
			}
		}
	}()

	// Wait a moment to ensure session is fully established
	time.Sleep(100 * time.Millisecond)

	// Now shutdown the proxy
	t.Log("Initiating proxy shutdown after authentication...")
	proxy.Close()

	// Wait for either BYE message or error
	select {
	case byeLine := <-byeReceived:
		t.Logf("✓ Received BYE message: %s", byeLine)
		if !strings.Contains(byeLine, "TRYLATER") {
			t.Errorf("BYE message doesn't contain TRYLATER: %s", byeLine)
		}
		if !strings.Contains(byeLine, "shutting down") {
			t.Errorf("BYE message doesn't mention shutdown: %s", byeLine)
		}
	case err := <-readError:
		t.Errorf("Connection closed without BYE message: %v", err)
	case <-time.After(3 * time.Second):
		t.Error("Timeout waiting for BYE message")
	}

	t.Log("✓ Proxy shutdown completed")
}
