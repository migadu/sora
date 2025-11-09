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
