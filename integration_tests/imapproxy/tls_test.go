//go:build integration

package imapproxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

// TestIMAPProxyImplicitTLS verifies that the proxy accepts connections over implicit TLS (port 993 style)
func TestIMAPProxyImplicitTLS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Load test certificates
	cert, err := tls.LoadX509KeyPair("../../testdata/sora.crt", "../../testdata/sora.key")
	if err != nil {
		t.Fatalf("Failed to load certificates: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Setup backend server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Setup proxy with TLS enabled
	proxyAddress := common.GetRandomAddress(t)
	hostname := "test-proxy-tls"

	opts := imapproxy.ServerOptions{
		Name:                   hostname,
		Addr:                   proxyAddress,
		RemoteAddrs:            []string{backendServer.Address},
		RemotePort:             143,
		MasterSASLUsername:     "proxyuser",
		MasterSASLPassword:     "proxypass",
		TLS:                    true,
		TLSConfig:              tlsConfig, // Use global TLS config
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
	}

	proxy, err := imapproxy.New(context.Background(), backendServer.ResilientDB, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy with TLS: %v", err)
	}

	// Start proxy
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP proxy error: %w", err)
		}
	}()
	defer proxy.Stop()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	// Connect with TLS
	conn, err := tls.Dial("tcp", proxyAddress, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("Failed to connect to proxy with TLS: %v", err)
	}
	defer conn.Close()

	// Verify handshake complete
	state := conn.ConnectionState()
	if !state.HandshakeComplete {
		t.Fatal("TLS handshake not complete")
	}
	t.Logf("✓ TLS handshake complete. Cipher suite: %s", tls.CipherSuiteName(state.CipherSuite))

	// Read greeting
	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("Invalid greeting: %s", greeting)
	}
	t.Logf("✓ Received greeting over TLS: %s", strings.TrimSpace(greeting))

	// Try to login
	loginCmd := fmt.Sprintf("a001 LOGIN %s %s\r\n", account.Email, account.Password)
	if _, err := conn.Write([]byte(loginCmd)); err != nil {
		t.Fatalf("Failed to send LOGIN: %v", err)
	}

	// Read response
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read LOGIN response: %v", err)
	}
	if !strings.Contains(response, "OK") {
		t.Fatalf("Login failed: %s", response)
	}
	t.Log("✓ Login successful over TLS")
}

// TestIMAPProxyJA4Fingerprint verifies that JA4 fingerprints are generated for TLS connections
func TestIMAPProxyJA4Fingerprint(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Capture logs to check for JA4
	logCapture := NewLogCapture()
	defer func() {
		logs := logCapture.Stop()
		if !strings.Contains(logs, "ja4=") {
			t.Errorf("Expected to find 'ja4=' entries in logs, but none found. Logs:\n%s", logs)
		} else {
			t.Log("✓ Verified 'ja4=' entries present in logs")
		}
	}()

	// Load test certificates
	cert, err := tls.LoadX509KeyPair("../../testdata/sora.crt", "../../testdata/sora.key")
	if err != nil {
		t.Fatalf("Failed to load certificates: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Setup backend server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Setup proxy with TLS enabled and Debug logging (to see JA4 logs)
	proxyAddress := common.GetRandomAddress(t)
	hostname := "test-proxy-ja4"

	opts := imapproxy.ServerOptions{
		Name:                   hostname,
		Addr:                   proxyAddress,
		RemoteAddrs:            []string{backendServer.Address},
		RemotePort:             143,
		MasterSASLUsername:     "proxyuser",
		MasterSASLPassword:     "proxypass",
		TLS:                    true,
		TLSConfig:              tlsConfig,
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		Debug:                  true, // Enable debug logging
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
	}

	proxy, err := imapproxy.New(context.Background(), backendServer.ResilientDB, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy with TLS: %v", err)
	}

	// Start proxy
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP proxy error: %w", err)
		}
	}()
	defer proxy.Stop()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	// Connect with TLS
	conn, err := tls.Dial("tcp", proxyAddress, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("Failed to connect to proxy with TLS: %v", err)
	}
	defer conn.Close()

	// Perform login to generate logs
	reader := bufio.NewReader(conn)
	// Read greeting
	_, _ = reader.ReadString('\n')

	// Login
	loginCmd := fmt.Sprintf("a001 LOGIN %s %s\r\n", account.Email, account.Password)
	conn.Write([]byte(loginCmd))
	_, _ = reader.ReadString('\n')

	t.Log("✓ Connection and login completed, checking logs for JA4...")
}
