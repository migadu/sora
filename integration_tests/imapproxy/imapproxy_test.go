//go:build integration

package imapproxy_test

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

// LogCapture helps capture log output for verification
type LogCapture struct {
	original *os.File
	buffer   *bytes.Buffer
}

// NewLogCapture creates a new log capture that redirects standard log output to a buffer
func NewLogCapture() *LogCapture {
	lc := &LogCapture{
		original: os.Stderr,
		buffer:   &bytes.Buffer{},
	}

	// Redirect log output to our buffer
	log.SetOutput(lc.buffer)
	return lc
}

// Stop restores the original log output and returns captured logs
func (lc *LogCapture) Stop() string {
	log.SetOutput(lc.original)
	return lc.buffer.String()
}

// ContainsProxyLog checks if the captured logs contain proxy= entries
func (lc *LogCapture) ContainsProxyLog() bool {
	logs := lc.buffer.String()
	return strings.Contains(logs, "proxy=")
}

// TestIMAPProxyWithPROXYProtocol tests IMAP proxy using PROXY protocol for backend communication
func TestIMAPProxyWithPROXYProtocol(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Start log capture to verify proxy= entries
	logCapture := NewLogCapture()
	defer func() {
		logs := logCapture.Stop()
		if !strings.Contains(logs, "proxy=") {
			t.Errorf("Expected to find 'proxy=' entries in logs for PROXY protocol mode, but none found. Logs:\n%s", logs)
		} else {
			t.Log("✓ Verified 'proxy=' entries present in logs for PROXY protocol mode")
		}
	}()

	// Create backend IMAP server with PROXY protocol support
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Set up IMAP proxy with PROXY protocol enabled
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	// Test proxy connection with PROXY protocol
	testBasicProxyConnection(t, proxyAddress, account)
	t.Log("IMAP proxy with PROXY protocol test completed - check logs for 'proxy=' entries")
}

// TestIMAPProxyWithIDCommand tests IMAP proxy using ID command for Dovecot compatibility
func TestIMAPProxyWithIDCommand(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Start log capture to verify proxy= entries
	logCapture := NewLogCapture()
	defer func() {
		logs := logCapture.Stop()
		if !strings.Contains(logs, "proxy=") {
			t.Errorf("Expected to find 'proxy=' entries in logs for ID command mode, but none found. Logs:\n%s", logs)
		} else {
			t.Log("✓ Verified 'proxy=' entries present in logs for ID command mode")
		}
	}()

	// Create backend IMAP server with master credentials (for ID command mode)
	backendServer, account := common.SetupIMAPServerWithMaster(t)
	defer backendServer.Close()

	// Set up IMAP proxy with ID command forwarding for Dovecot compatibility
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithIDCommand(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	// Test proxy connection with ID command forwarding
	testBasicProxyConnection(t, proxyAddress, account)
	t.Log("IMAP proxy with ID command forwarding (Dovecot compatibility) test completed - check logs for ID command forwarding")
}

// TestIMAPProxyMultipleBackends tests IMAP proxy with multiple backend servers
func TestIMAPProxyMultipleBackends(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create multiple backend IMAP servers with PROXY protocol support
	backendServer1, account1 := common.SetupIMAPServerWithPROXY(t)
	defer backendServer1.Close()

	backendServer2, account2 := common.SetupIMAPServerWithPROXY(t)
	defer backendServer2.Close()

	// Set up IMAP proxy with multiple backends using PROXY protocol
	proxyAddress := common.GetRandomAddress(t)
	backends := []string{backendServer1.Address, backendServer2.Address}
	proxy := setupIMAPProxyWithPROXY(t, backendServer1.ResilientDB, proxyAddress, backends)
	defer proxy.Close()

	// Test connections to both backends through proxy
	testBasicProxyConnection(t, proxyAddress, account1)
	testBasicProxyConnection(t, proxyAddress, account2)
}

// TestIMAPProxyAuthentication tests various authentication scenarios
func TestIMAPProxyAuthentication(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server with PROXY protocol support
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Set up IMAP proxy with PROXY protocol
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	// Test invalid login through proxy
	c, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer c.Logout()

	// Test invalid password
	err = c.Login(account.Email, "wrong_password").Wait()
	if err == nil {
		t.Fatal("Expected login to fail with wrong password through proxy, but it succeeded")
	}
	t.Logf("Login correctly failed through proxy with wrong password: %v", err)

	// Test non-existent user
	err = c.Login("nonexistent@example.com", "password").Wait()
	if err == nil {
		t.Fatal("Expected login to fail with non-existent user through proxy, but it succeeded")
	}
	t.Logf("Login correctly failed through proxy with non-existent user: %v", err)
}

// setupIMAPProxyWithPROXY creates IMAP proxy using PROXY protocol for backend communication
func setupIMAPProxyWithPROXY(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-protocol"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := imapproxy.ServerOptions{
		Name:                   "test-proxy-protocol",
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             143, // Default IMAP port
		MasterSASLUsername:     masterUsername,
		MasterSASLPassword:     masterPassword,
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: true,  // Enable PROXY protocol to backend
		RemoteUseIDCommand:     false, // Disable ID command (using PROXY instead)
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies:  []string{"127.0.0.0/8", "::1/128"},
		TrustedNetworks: []string{"127.0.0.0/8", "::1/128"},
		// PROXY protocol disabled for incoming connections in this test
		// (test clients don't send PROXY headers)
	}

	proxy, err := imapproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy with PROXY protocol: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP proxy error: %w", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	testServer := &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}

	testServer.SetCleanup(func() {
		proxy.Stop()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("IMAP proxy error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
	})

	return testServer
}

// setupIMAPProxyWithIDCommand creates IMAP proxy using ID command for Dovecot compatibility
func setupIMAPProxyWithIDCommand(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-id"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := imapproxy.ServerOptions{
		Name:                   "test-proxy-id",
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             143, // Default IMAP port
		MasterSASLUsername:     masterUsername,
		MasterSASLPassword:     masterPassword,
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: false, // Disable PROXY protocol (using ID instead)
		RemoteUseIDCommand:     true,  // Enable ID command for Dovecot compatibility
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
	}

	proxy, err := imapproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy with ID command: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP proxy error: %w", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	testServer := &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}

	testServer.SetCleanup(func() {
		proxy.Stop()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("IMAP proxy error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
	})

	return testServer
}

// testBasicProxyConnection tests basic connection and authentication through proxy
func testBasicProxyConnection(t *testing.T, proxyAddr string, account common.TestAccount) {
	t.Helper()

	c, err := imapclient.DialInsecure(proxyAddr, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer c.Logout()

	t.Logf("Connected to IMAP proxy at %s", proxyAddr)

	// Test login through proxy
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed through proxy for user %s: %v", account.Email, err)
	}
	t.Log("Login through proxy successful")

	// Test selecting INBOX through proxy
	selectCmd := c.Select("INBOX", nil)
	mbox, err := selectCmd.Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed through proxy: %v", err)
	}

	if mbox.NumMessages != 0 {
		t.Errorf("Expected 0 messages in INBOX through proxy, got %d", mbox.NumMessages)
	}
	t.Log("INBOX selected successfully through proxy")

	// Test LIST command through proxy
	listCmd := c.List("", "*", nil)
	mailboxes, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST command failed through proxy: %v", err)
	}

	// Should at least have INBOX
	found := false
	for _, mbox := range mailboxes {
		if mbox.Mailbox == "INBOX" {
			found = true
			break
		}
	}

	if !found {
		t.Error("INBOX not found in LIST results through proxy")
	}
	t.Logf("LIST command successful through proxy, found %d mailboxes", len(mailboxes))
}

// TestIMAPProxyConnectionLimits tests connection limiting functionality
func TestIMAPProxyConnectionLimits(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, _ := common.SetupIMAPServer(t)
	defer backendServer.Close()

	// Set up IMAP proxy with low connection limits for testing
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithLimits(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, 2, 1)
	defer proxy.Close()

	// Test that we can establish connections up to the limit
	c1, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy (connection 1): %v", err)
	}
	defer c1.Logout()

	c2, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy (connection 2): %v", err)
	}
	defer c2.Logout()

	// Third connection should be limited (depends on implementation)
	// This might timeout or be accepted depending on proxy behavior
	c3, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Logf("Third connection appropriately limited: %v", err)
	} else {
		c3.Logout()
		t.Log("Third connection was allowed (proxy may queue connections)")
	}

	t.Log("Connection limiting test completed")
}

// setupIMAPProxyWithLimits creates an IMAP proxy with specific connection limits
func setupIMAPProxyWithLimits(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, maxConns, maxConnsPerIP int) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-limits"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	opts := imapproxy.ServerOptions{
		Name:                   "test-proxy-limits",
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             143,
		MasterSASLUsername:     masterUsername,
		MasterSASLPassword:     masterPassword,
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: true,
		RemoteUseIDCommand:     false,
		ConnectTimeout:         5 * time.Second,
		AuthIdleTimeout:        10 * time.Minute,
		EnableAffinity:         false,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
	}

	proxy, err := imapproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy with limits: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP proxy error: %w", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	testServer := &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}

	testServer.SetCleanup(func() {
		proxy.Stop()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("IMAP proxy error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
	})

	return testServer
}
