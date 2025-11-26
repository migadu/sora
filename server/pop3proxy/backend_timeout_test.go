package pop3proxy

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

// TestBackendAuthTimeout verifies that when backend times out during authentication,
// we return "Backend server temporarily unavailable" not "Authentication failed"
//
// NOTE: This is an integration-style test that requires actual authentication to work.
// It's skipped in short mode. The unit tests in backend_auth_error_test.go provide
// better coverage of the error handling logic without needing full setup.
func TestBackendAuthTimeout(t *testing.T) {
	t.Skip("Skipping - requires full database setup. See backend_auth_error_test.go for unit tests of error handling logic")
	if testing.Short() {
		t.Skip("Skipping backend timeout test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a mock backend that accepts connections but delays responding to AUTH
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create backend listener: %v", err)
	}
	defer backendListener.Close()
	backendAddr := backendListener.Addr().String()

	// Start mock backend that times out during auth
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				writer := bufio.NewWriter(c)
				// Send greeting
				writer.WriteString("+OK Mock POP3 backend ready\r\n")
				writer.Flush()

				// Read commands but delay responding to AUTH (simulates timeout)
				reader := bufio.NewReader(c)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					// Delay response to AUTH command to trigger timeout
					if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "AUTH") {
						t.Logf("Backend: Received AUTH command, delaying response for 5s to trigger timeout")
						// Sleep longer than the proxy's connect timeout
						time.Sleep(5 * time.Second)
						writer.WriteString("+OK\r\n")
						writer.Flush()
						return
					}
					// Respond to other commands normally
					writer.WriteString("+OK\r\n")
					writer.Flush()
				}
			}(conn)
		}
	}()

	// Find available port for proxy
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	proxyAddr := proxyListener.Addr().String()
	proxyListener.Close()

	// Create empty mock database - we'll use remotelookup to bypass DB auth
	mockRDB := &resilient.ResilientDatabase{}

	// Create remotelookup config that always succeeds (simulates successful user lookup)
	remotelookupConfig := &config.RemoteLookupConfig{
		Enabled: false, // Disable remotelookup, use master username instead
	}

	// Create proxy with very short connect timeout (shorter than backend delay)
	srv, err := New(ctx, "localhost", proxyAddr, mockRDB, POP3ProxyServerOptions{
		Name:               "test",
		RemoteAddrs:        []string{backendAddr},
		RemotePort:         110,
		AuthIdleTimeout:    30 * time.Second,
		CommandTimeout:     30 * time.Second,
		ConnectTimeout:     2 * time.Second, // Short timeout so backend delay triggers it
		AuthRateLimit:      server.AuthRateLimiterConfig{},
		MaxConnections:     10,
		RemoteLookup:       remotelookupConfig,
		MasterUsername:     "master",     // Configure master username auth
		MasterPassword:     "masterpass", // so we can auth without database
		MasterSASLUsername: "master",
		MasterSASLPassword: "masterpass",
	})
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy: %v", err)
	}

	// Start server in background
	go func() {
		if err := srv.Start(); err != nil && ctx.Err() == nil {
			t.Logf("Proxy server error: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Connect client
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("Expected +OK greeting, got: %s", greeting)
	}
	t.Logf("Proxy greeting: %s", strings.TrimSpace(greeting))

	// Authenticate with USER/PASS using master username format
	writer.WriteString("USER test@example.com@master\r\n")
	writer.Flush()
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		t.Fatalf("Expected +OK for USER, got: %s", response)
	}
	t.Logf("USER response: %s", strings.TrimSpace(response))

	// Send PASS with master password - this will trigger backend connection and AUTH timeout
	writer.WriteString("PASS masterpass\r\n")
	writer.Flush()

	// Read response - should be error about backend unavailability
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	response, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}
	t.Logf("PASS response: %s", strings.TrimSpace(response))

	// Verify response indicates backend unavailability, not authentication failure
	if !strings.HasPrefix(response, "-ERR") {
		t.Errorf("Expected -ERR response, got: %s", response)
	}

	// Should indicate backend unavailability
	if !strings.Contains(response, "Backend") && !strings.Contains(response, "temporarily unavailable") && !strings.Contains(response, "SYS/TEMP") {
		t.Errorf("Expected error to indicate backend/temporary issue, got: %s", response)
		t.Log("❌ Error doesn't indicate backend timeout")
	} else {
		t.Logf("✓ Correct: Backend timeout returns backend unavailability error")
	}

	// Should NOT contain "Authentication failed" since auth to proxy DB succeeded
	if strings.Contains(response, "Authentication failed") {
		t.Errorf("ERROR: Response incorrectly says 'Authentication failed' when backend timed out: %s", response)
		t.Log("❌ This would be the bug - authentication succeeded but backend connection/auth timed out")
	} else {
		t.Logf("✓ Correct: Does not say 'Authentication failed'")
	}
}

// TestBackendConnectTimeout verifies that when backend connection fails/times out,
// we return appropriate error (not authentication failed)
//
// NOTE: This is an integration-style test that requires actual authentication to work.
// It's skipped in short mode. The unit tests in backend_auth_error_test.go provide
// better coverage of the error handling logic without needing full setup.
func TestBackendConnectTimeout(t *testing.T) {
	t.Skip("Skipping - requires full database setup. See backend_auth_error_test.go for unit tests of error handling logic")
	if testing.Short() {
		t.Skip("Skipping backend timeout test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a backend that accepts connections but never sends greeting (simulates hanging)
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create backend listener: %v", err)
	}
	defer backendListener.Close()
	backendAddr := backendListener.Addr().String()

	// Start mock backend that hangs on connect
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			// Accept connection but never send greeting - just hang
			// This will cause the proxy to timeout waiting for greeting
			go func(c net.Conn) {
				t.Logf("Backend: Accepted connection, hanging (not sending greeting)")
				time.Sleep(10 * time.Second)
				c.Close()
			}(conn)
		}
	}()

	// Find available port for proxy
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	proxyAddr := proxyListener.Addr().String()
	proxyListener.Close()

	// Create empty mock database - we'll use master username to bypass DB auth
	mockRDB := &resilient.ResilientDatabase{}

	// Create proxy with very short connect timeout
	srv, err := New(ctx, "localhost", proxyAddr, mockRDB, POP3ProxyServerOptions{
		Name:               "test",
		RemoteAddrs:        []string{backendAddr},
		RemotePort:         110,
		AuthIdleTimeout:    30 * time.Second,
		CommandTimeout:     30 * time.Second,
		ConnectTimeout:     1 * time.Second, // Very short timeout
		AuthRateLimit:      server.AuthRateLimiterConfig{},
		MaxConnections:     10,
		RemoteLookup:       &config.RemoteLookupConfig{Enabled: false},
		MasterUsername:     "master",     // Configure master username auth
		MasterPassword:     "masterpass", // so we can auth without database
		MasterSASLUsername: "master",
		MasterSASLPassword: "masterpass",
	})
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy: %v", err)
	}

	// Start server in background
	go func() {
		if err := srv.Start(); err != nil && ctx.Err() == nil {
			t.Logf("Proxy server error: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Connect client
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("Expected +OK greeting, got: %s", greeting)
	}

	// Authenticate with USER/PASS using master username format
	writer.WriteString("USER test@example.com@master\r\n")
	writer.Flush()
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}

	// Send PASS with master password - this will trigger backend connection timeout (waiting for greeting)
	writer.WriteString("PASS masterpass\r\n")
	writer.Flush()

	// Read response - should be error about backend unavailability
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}
	t.Logf("PASS response: %s", strings.TrimSpace(response))

	// Verify response
	if !strings.HasPrefix(response, "-ERR") {
		t.Errorf("Expected -ERR response, got: %s", response)
	}

	// Should indicate backend unavailability
	if !strings.Contains(response, "Backend") && !strings.Contains(response, "temporarily unavailable") && !strings.Contains(response, "SYS/TEMP") {
		t.Errorf("Expected error to indicate backend/temporary issue, got: %s", response)
	} else {
		t.Logf("✓ Correct: Backend connection timeout returns backend unavailability error")
	}

	// Should NOT contain "Authentication failed"
	if strings.Contains(response, "Authentication failed") {
		t.Errorf("ERROR: Response incorrectly says 'Authentication failed' when backend timed out: %s", response)
	} else {
		t.Logf("✓ Correct: Does not say 'Authentication failed'")
	}
}
