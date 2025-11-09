//go:build integration

package managesieve_test

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestManageSieveBackendGracefulShutdownBeforeAuth tests that clients receive BYE message
// during graceful shutdown when they are in pre-auth state (after greeting, before AUTHENTICATE).
func TestManageSieveBackendGracefulShutdownBeforeAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := common.SetupManageSieveServer(t)

	// Connect with raw TCP connection to capture responses
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to dial ManageSieve server: %v", err)
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

	// Now shutdown the server
	t.Log("Initiating server shutdown...")
	shutdownDone := make(chan struct{})
	go func() {
		server.Close()
		close(shutdownDone)
	}()

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

	// Wait for shutdown to complete
	<-shutdownDone
	t.Log("✓ Server shutdown completed")
}

// TestManageSieveBackendGracefulShutdownDuringAuth tests that clients receive BYE message
// during graceful shutdown when they are attempting to authenticate.
func TestManageSieveBackendGracefulShutdownDuringAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupManageSieveServer(t)

	// Connect with raw TCP connection
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to dial ManageSieve server: %v", err)
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

	// Start goroutine to send AUTHENTICATE and wait very short time before shutdown
	authSent := make(chan struct{})
	go func() {
		fmt.Fprintf(conn, "AUTHENTICATE \"PLAIN\" \"%s\"\r\n", encoded)
		close(authSent)
	}()

	// Wait for auth to be sent
	<-authSent

	// Shutdown almost immediately (racing with authentication)
	time.Sleep(1 * time.Millisecond)

	t.Log("Initiating server shutdown during authentication...")
	shutdownDone := make(chan struct{})
	go func() {
		server.Close()
		close(shutdownDone)
	}()

	// Read response - could be OK (auth succeeded before shutdown) or BYE (shutdown during auth)
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

	// Wait for shutdown to complete
	<-shutdownDone
	t.Log("✓ Server shutdown completed")
}

// TestManageSieveBackendGracefulShutdownAfterAuth tests that clients receive BYE message
// during graceful shutdown when they are already authenticated.
func TestManageSieveBackendGracefulShutdownAfterAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupManageSieveServer(t)

	// Connect with raw TCP connection
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to dial ManageSieve server: %v", err)
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

	// Now shutdown the server
	t.Log("Initiating server shutdown after authentication...")
	shutdownDone := make(chan struct{})
	go func() {
		server.Close()
		close(shutdownDone)
	}()

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

	// Wait for shutdown to complete
	<-shutdownDone
	t.Log("✓ Server shutdown completed")
}
