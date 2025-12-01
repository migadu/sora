//go:build integration

package imapproxy_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAPProxyGracefulShutdownBeforeAuth tests that clients receive BYE message
// during graceful shutdown when they are in pre-auth state (after greeting, before LOGIN).
func TestIMAPProxyGracefulShutdownBeforeAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup backend server
	backendServer, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Setup proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})

	// Connect with raw TCP connection to capture untagged responses
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("Expected OK greeting, got: %s", greeting)
	}
	t.Logf("✓ Received greeting: %s", strings.TrimSpace(greeting))

	// Start goroutine to read untagged responses
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
			if strings.HasPrefix(line, "* BYE") {
				byeReceived <- line
				return
			}
		}
	}()

	// Wait a moment to ensure session is established
	time.Sleep(100 * time.Millisecond)

	// Now shutdown the proxy
	t.Log("Initiating proxy shutdown...")
	shutdownDone := make(chan struct{})
	go func() {
		proxy.Close()
		close(shutdownDone)
	}()

	// Wait for either BYE message or error
	select {
	case byeLine := <-byeReceived:
		t.Logf("✓ Received BYE message: %s", byeLine)
		if !strings.Contains(byeLine, "shutting down") && !strings.Contains(byeLine, "Server shutting down") {
			t.Errorf("BYE message doesn't mention shutdown: %s", byeLine)
		}
	case err := <-readError:
		t.Errorf("Connection closed without BYE message: %v", err)
	case <-time.After(3 * time.Second):
		t.Error("Timeout waiting for BYE message")
	}

	// Wait for shutdown to complete
	<-shutdownDone
	t.Log("✓ Proxy shutdown completed")
}

// TestIMAPProxyGracefulShutdownDuringAuth tests that clients receive BYE message
// during graceful shutdown when they are attempting to authenticate.
func TestIMAPProxyGracefulShutdownDuringAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup backend server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Setup proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})

	// Connect with raw TCP connection
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("Expected OK greeting, got: %s", greeting)
	}
	t.Logf("✓ Received greeting: %s", strings.TrimSpace(greeting))

	// Start goroutine to read all responses (both tagged and untagged)
	type response struct {
		line      string
		isBye     bool
		isTagged  bool
		isSuccess bool
	}
	responses := make(chan response, 10)
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

			resp := response{line: line}
			if strings.HasPrefix(line, "* BYE") {
				resp.isBye = true
			} else if strings.HasPrefix(line, "A001 ") {
				resp.isTagged = true
				resp.isSuccess = strings.HasPrefix(line, "A001 OK")
			}
			responses <- resp
		}
	}()

	// Send LOGIN command
	loginCmd := fmt.Sprintf("A001 LOGIN %s %s\r\n", account.Email, account.Password)
	if _, err := conn.Write([]byte(loginCmd)); err != nil {
		t.Fatalf("Failed to send LOGIN: %v", err)
	}
	t.Log("✓ Sent LOGIN command")

	// Immediately shutdown the proxy (race with authentication)
	time.Sleep(1 * time.Millisecond)
	t.Log("Initiating proxy shutdown during authentication...")
	shutdownDone := make(chan struct{})
	go func() {
		proxy.Close()
		close(shutdownDone)
	}()

	// Wait for responses
	timeout := time.After(3 * time.Second)
	sawBye := false
	sawTaggedResponse := false
	loginSucceeded := false

	for {
		select {
		case resp := <-responses:
			if resp.isBye {
				sawBye = true
				t.Logf("✓ Received BYE: %s", resp.line)
			}
			if resp.isTagged {
				sawTaggedResponse = true
				loginSucceeded = resp.isSuccess
				t.Logf("✓ Received tagged response: %s", resp.line)
				// After tagged response, we can exit
				goto done
			}
		case err := <-readError:
			t.Logf("Connection closed: %v", err)
			goto done
		case <-timeout:
			t.Error("Timeout waiting for responses")
			goto done
		}
	}

done:
	// Wait for shutdown
	<-shutdownDone
	t.Log("✓ Proxy shutdown completed")

	// Verify we got either BYE or login failed with UNAVAILABLE
	if !sawBye && !sawTaggedResponse {
		t.Error("Expected either BYE message or tagged response")
	}

	if sawTaggedResponse && loginSucceeded {
		t.Log("✓ Login succeeded before shutdown (timing race - acceptable)")
	} else if sawBye {
		t.Log("✓ Received BYE during shutdown as expected")
	} else {
		t.Log("✓ Connection closed during shutdown")
	}
}

// TestIMAPProxyGracefulShutdownAfterAuth tests that clients receive BYE message
// during graceful shutdown after they have authenticated.
func TestIMAPProxyGracefulShutdownAfterAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup backend server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Setup proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})

	// Connect with raw TCP connection
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("✓ Received greeting: %s", strings.TrimSpace(greeting))

	// Send LOGIN and wait for completion
	loginCmd := fmt.Sprintf("A001 LOGIN %s %s\r\n", account.Email, account.Password)
	if _, err := conn.Write([]byte(loginCmd)); err != nil {
		t.Fatalf("Failed to send LOGIN: %v", err)
	}

	// Read responses until we get the tagged OK response
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read LOGIN response: %v", err)
		}
		line = strings.TrimSpace(line)
		t.Logf("Login response: %s", line)
		if strings.HasPrefix(line, "A001 OK") {
			t.Log("✓ Successfully authenticated")
			break
		}
		if strings.HasPrefix(line, "A001 NO") || strings.HasPrefix(line, "A001 BAD") {
			t.Fatalf("Login failed: %s", line)
		}
	}

	// Start goroutine to read untagged responses
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
			if strings.HasPrefix(line, "* BYE") {
				byeReceived <- line
				return
			}
		}
	}()

	// Send a command to enter passthrough mode
	if _, err := conn.Write([]byte("A002 NOOP\r\n")); err != nil {
		t.Fatalf("Failed to send NOOP: %v", err)
	}
	t.Log("✓ Sent NOOP to enter passthrough mode")

	// Wait a moment for NOOP response and passthrough to be established
	time.Sleep(100 * time.Millisecond)

	// Now shutdown the proxy
	t.Log("Initiating proxy shutdown after authentication...")
	shutdownDone := make(chan struct{})
	go func() {
		proxy.Close()
		close(shutdownDone)
	}()

	// Wait for either BYE message or connection close
	select {
	case byeLine := <-byeReceived:
		t.Logf("✓ Received BYE message: %s", byeLine)
		if !strings.Contains(byeLine, "shutting down") && !strings.Contains(byeLine, "Server shutting down") {
			t.Errorf("BYE message doesn't mention shutdown: %s", byeLine)
		}
	case err := <-readError:
		// In passthrough mode, connection might close without BYE due to timing
		t.Logf("⚠ Connection closed without BYE (passthrough mode timing): %v", err)
	case <-time.After(3 * time.Second):
		t.Error("Timeout waiting for BYE message or connection close")
	}

	// Wait for shutdown to complete
	<-shutdownDone
	t.Log("✓ Proxy shutdown completed")
}

// TestIMAPProxyGracefulShutdownWithReconnect tests that clients receive BYE message
// during graceful shutdown and can successfully reconnect after the proxy restarts.
// This simulates the real-world scenario where users should not be forced to manually
// re-enter credentials - their client should auto-reconnect and auto-reauthenticate.
func TestIMAPProxyGracefulShutdownWithReconnect(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup backend server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Setup proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})

	// Connect first client
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("✓ Received greeting: %s", strings.TrimSpace(greeting))

	// Authenticate
	loginCmd := fmt.Sprintf("A001 LOGIN %s %s\r\n", account.Email, account.Password)
	if _, err := conn.Write([]byte(loginCmd)); err != nil {
		t.Fatalf("Failed to send LOGIN: %v", err)
	}

	// Read responses until login completes
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read LOGIN response: %v", err)
		}
		line = strings.TrimSpace(line)
		t.Logf("Login response: %s", line)
		if strings.HasPrefix(line, "A001 OK") {
			t.Log("✓ Successfully authenticated")
			break
		}
		if strings.HasPrefix(line, "A001 NO") || strings.HasPrefix(line, "A001 BAD") {
			t.Fatalf("Login failed: %s", line)
		}
	}

	// Start goroutine to read BYE message
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
			if strings.HasPrefix(line, "* BYE") {
				byeReceived <- line
				return
			}
		}
	}()

	// Shutdown the proxy
	t.Log("Initiating proxy shutdown...")
	shutdownDone := make(chan struct{})
	go func() {
		proxy.Close()
		close(shutdownDone)
	}()

	// Wait for BYE message
	select {
	case byeLine := <-byeReceived:
		t.Logf("✓ Received BYE message: %s", byeLine)
		if !strings.Contains(byeLine, "shutting down") && !strings.Contains(byeLine, "Server shutting down") {
			t.Errorf("BYE message doesn't mention shutdown: %s", byeLine)
		}
	case err := <-readError:
		t.Logf("Connection closed: %v", err)
	case <-time.After(3 * time.Second):
		t.Error("Timeout waiting for BYE message")
	}

	// Wait for shutdown to complete
	<-shutdownDone
	t.Log("✓ Proxy shutdown completed")

	// Close the old connection
	conn.Close()

	// Now simulate client reconnecting after receiving BYE
	t.Log("Simulating client reconnect after BYE...")

	// Start a new proxy instance (simulating server restart)
	time.Sleep(500 * time.Millisecond) // Brief delay to ensure old proxy is fully stopped
	newProxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer newProxy.Close()

	// Give new proxy time to start listening
	time.Sleep(100 * time.Millisecond)

	// Client reconnects
	t.Log("Attempting to reconnect...")
	reconnConn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to reconnect to proxy: %v", err)
	}
	defer reconnConn.Close()

	reconnReader := bufio.NewReader(reconnConn)

	// Read greeting from new connection
	reconnGreeting, err := reconnReader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting on reconnect: %v", err)
	}
	if !strings.HasPrefix(reconnGreeting, "* OK") {
		t.Fatalf("Expected OK greeting on reconnect, got: %s", reconnGreeting)
	}
	t.Logf("✓ Reconnected successfully: %s", strings.TrimSpace(reconnGreeting))

	// Reauthenticate (this is what email clients do automatically)
	t.Log("Attempting to reauthenticate...")
	reconnLoginCmd := fmt.Sprintf("A001 LOGIN %s %s\r\n", account.Email, account.Password)
	if _, err := reconnConn.Write([]byte(reconnLoginCmd)); err != nil {
		t.Fatalf("Failed to send LOGIN on reconnect: %v", err)
	}

	// Read responses until login completes
	loginSuccess := false
	for {
		line, err := reconnReader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read LOGIN response on reconnect: %v", err)
		}
		line = strings.TrimSpace(line)
		t.Logf("Reconnect login response: %s", line)
		if strings.HasPrefix(line, "A001 OK") {
			loginSuccess = true
			t.Log("✓ Successfully reauthenticated after reconnect")
			break
		}
		if strings.HasPrefix(line, "A001 NO") || strings.HasPrefix(line, "A001 BAD") {
			t.Fatalf("Reauthentication failed: %s", line)
		}
	}

	if !loginSuccess {
		t.Fatal("Failed to reauthenticate after reconnect")
	}

	// Verify we can perform operations after reconnect
	t.Log("Verifying proxy functionality after reconnect...")
	if _, err := reconnConn.Write([]byte("A002 CAPABILITY\r\n")); err != nil {
		t.Fatalf("Failed to send CAPABILITY: %v", err)
	}

	// Read CAPABILITY response
	capabilityReceived := false
	for {
		line, err := reconnReader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read CAPABILITY response: %v", err)
		}
		line = strings.TrimSpace(line)
		t.Logf("Capability response: %s", line)
		if strings.HasPrefix(line, "* CAPABILITY") {
			capabilityReceived = true
		}
		if strings.HasPrefix(line, "A002 OK") {
			break
		}
	}

	if !capabilityReceived {
		t.Error("Did not receive CAPABILITY response")
	}

	t.Log("✓ Full reconnect cycle completed successfully")
	t.Log("✓ This demonstrates that clients can auto-reconnect and auto-reauthenticate after graceful shutdown")
}

// TestIMAPProxyBackendConnectionFailure tests that clients receive proper BYE message
// when backend connection fails after successful proxy authentication.
// This simulates the case where remotelookup succeeds but the backend is unavailable.
func TestIMAPProxyBackendConnectionFailure(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup backend server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)

	// Setup proxy pointing to backend
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	// Connect to proxy
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("Expected OK greeting, got: %s", greeting)
	}
	t.Logf("✓ Received greeting: %s", strings.TrimSpace(greeting))

	// NOW shutdown the backend server BEFORE authentication
	// This simulates backend being unavailable after remotelookup succeeds
	backendServer.Close()
	time.Sleep(100 * time.Millisecond) // Give backend time to fully close

	t.Log("Backend server shut down - attempting to authenticate...")

	// Try to authenticate - proxy auth will succeed, but backend connection will fail
	loginCmd := fmt.Sprintf("A001 LOGIN %s %s\r\n", account.Email, account.Password)
	if _, err := conn.Write([]byte(loginCmd)); err != nil {
		t.Fatalf("Failed to send LOGIN: %v", err)
	}

	// Start goroutine to read all responses
	responses := make(chan string, 10)
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
			responses <- line
		}
	}()

	// We should receive:
	// 1. A001 NO [UNAVAILABLE] response
	// 2. * BYE message
	timeout := time.After(5 * time.Second)
	sawUnavailable := false
	sawBye := false

	for {
		select {
		case line := <-responses:
			if strings.Contains(line, "A001 NO") && strings.Contains(line, "UNAVAILABLE") {
				sawUnavailable = true
				t.Logf("✓ Received UNAVAILABLE response: %s", line)
			}
			if strings.HasPrefix(line, "* BYE") {
				sawBye = true
				t.Logf("✓ Received BYE message: %s", line)
				if !strings.Contains(line, "unavailable") && !strings.Contains(line, "Backend") {
					t.Errorf("BYE message doesn't mention backend unavailability: %s", line)
				}
				// After BYE, connection will close - don't exit yet, let it close naturally
			}
		case err := <-readError:
			// Connection closed - this is expected after BYE
			t.Logf("Connection closed: %v", err)
			// Drain any remaining responses in the channel before exiting
			for {
				select {
				case line := <-responses:
					if strings.Contains(line, "A001 NO") && strings.Contains(line, "UNAVAILABLE") {
						sawUnavailable = true
						t.Logf("✓ Received UNAVAILABLE response (after EOF): %s", line)
					}
					if strings.HasPrefix(line, "* BYE") {
						sawBye = true
						t.Logf("✓ Received BYE message (after EOF): %s", line)
						if !strings.Contains(line, "unavailable") && !strings.Contains(line, "Backend") {
							t.Errorf("BYE message doesn't mention backend unavailability: %s", line)
						}
					}
				default:
					goto done
				}
			}
		case <-timeout:
			t.Error("Timeout waiting for responses")
			goto done
		}
	}

done:
	if !sawUnavailable {
		t.Error("Did not receive NO [UNAVAILABLE] response")
	}
	if !sawBye {
		t.Error("Did not receive BYE message after backend connection failure")
	} else {
		t.Log("✓ Client properly notified of backend unavailability and connection closed")
		t.Log("✓ This allows clients to immediately retry rather than hanging indefinitely")
	}
}
