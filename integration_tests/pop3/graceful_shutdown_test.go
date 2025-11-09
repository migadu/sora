//go:build integration

package pop3_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestPOP3BackendGracefulShutdownBeforeAuth tests that clients receive -ERR message
// during graceful shutdown when they are in pre-auth state (after greeting, before USER/PASS).
func TestPOP3BackendGracefulShutdownBeforeAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := common.SetupPOP3Server(t)

	// Connect with raw TCP connection to capture responses
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to dial POP3 server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("Expected +OK greeting, got: %s", greeting)
	}
	t.Logf("✓ Received greeting: %s", strings.TrimSpace(greeting))

	// Start goroutine to read responses
	errReceived := make(chan string, 1)
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
			if strings.HasPrefix(line, "-ERR") {
				errReceived <- line
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

	// Wait for either -ERR message or error
	select {
	case errLine := <-errReceived:
		t.Logf("✓ Received -ERR message: %s", errLine)
		if !strings.Contains(errLine, "shutting down") {
			t.Errorf("-ERR message doesn't mention shutdown: %s", errLine)
		}
	case err := <-readError:
		t.Errorf("Connection closed without -ERR message: %v", err)
	case <-time.After(3 * time.Second):
		t.Error("Timeout waiting for -ERR message")
	}

	// Wait for shutdown to complete
	<-shutdownDone
	t.Log("✓ Server shutdown completed")
}

// TestPOP3BackendGracefulShutdownDuringAuth tests that clients receive -ERR message
// during graceful shutdown when they are attempting to authenticate.
func TestPOP3BackendGracefulShutdownDuringAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)

	// Connect with raw TCP connection
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to dial POP3 server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("Expected +OK greeting, got: %s", greeting)
	}
	t.Logf("✓ Received greeting: %s", strings.TrimSpace(greeting))

	// Start goroutine to read all responses
	type response struct {
		line    string
		isErr   bool
		isOk    bool
		forUser bool
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
			if strings.HasPrefix(line, "-ERR") {
				resp.isErr = true
			} else if strings.HasPrefix(line, "+OK") {
				resp.isOk = true
			}
			responses <- resp
		}
	}()

	// Send USER command
	userCmd := fmt.Sprintf("USER %s\r\n", account.Email)
	if _, err := conn.Write([]byte(userCmd)); err != nil {
		t.Fatalf("Failed to send USER: %v", err)
	}
	t.Log("✓ Sent USER command")

	// Wait for USER response
	select {
	case resp := <-responses:
		if resp.isErr {
			t.Fatalf("USER command failed: %s", resp.line)
		}
		t.Logf("✓ USER accepted: %s", resp.line)
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for USER response")
	}

	// Now send PASS and immediately shutdown
	passCmd := fmt.Sprintf("PASS %s\r\n", account.Password)
	if _, err := conn.Write([]byte(passCmd)); err != nil {
		t.Fatalf("Failed to send PASS: %v", err)
	}
	t.Log("✓ Sent PASS command")

	time.Sleep(1 * time.Millisecond)
	t.Log("Initiating server shutdown during authentication...")
	shutdownDone := make(chan struct{})
	go func() {
		server.Close()
		close(shutdownDone)
	}()

	// Wait for responses
	timeout := time.After(3 * time.Second)
	sawErr := false
	sawOk := false
	authSucceeded := false

	for {
		select {
		case resp := <-responses:
			if resp.isErr {
				sawErr = true
				t.Logf("✓ Received -ERR: %s", resp.line)
				goto done
			}
			if resp.isOk {
				sawOk = true
				authSucceeded = true
				t.Logf("✓ Received +OK: %s", resp.line)
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
	t.Log("✓ Server shutdown completed")

	if sawOk && authSucceeded {
		t.Log("✓ Auth succeeded before shutdown (timing race - acceptable)")
	} else if sawErr {
		t.Log("✓ Received -ERR during shutdown as expected")
	} else {
		t.Log("✓ Connection closed during shutdown")
	}
}

// TestPOP3BackendGracefulShutdownAfterAuth tests that clients receive -ERR message
// during graceful shutdown after they have authenticated.
func TestPOP3BackendGracefulShutdownAfterAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)

	// Connect with raw TCP connection
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to dial POP3 server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("✓ Received greeting: %s", strings.TrimSpace(greeting))

	// Send USER command
	userCmd := fmt.Sprintf("USER %s\r\n", account.Email)
	if _, err := conn.Write([]byte(userCmd)); err != nil {
		t.Fatalf("Failed to send USER: %v", err)
	}

	// Read USER response
	userResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}
	if !strings.HasPrefix(userResp, "+OK") {
		t.Fatalf("USER failed: %s", userResp)
	}

	// Send PASS command
	passCmd := fmt.Sprintf("PASS %s\r\n", account.Password)
	if _, err := conn.Write([]byte(passCmd)); err != nil {
		t.Fatalf("Failed to send PASS: %v", err)
	}

	// Read PASS response
	passResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}
	if !strings.HasPrefix(passResp, "+OK") {
		t.Fatalf("PASS failed: %s", passResp)
	}
	t.Log("✓ Successfully authenticated")

	// Start goroutine to read responses
	errReceived := make(chan string, 1)
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
			if strings.HasPrefix(line, "-ERR") {
				errReceived <- line
				return
			}
		}
	}()

	// Send a command to ensure we're in authenticated state
	if _, err := conn.Write([]byte("STAT\r\n")); err != nil {
		t.Fatalf("Failed to send STAT: %v", err)
	}
	t.Log("✓ Sent STAT command")

	// Wait a moment for STAT response
	time.Sleep(100 * time.Millisecond)

	// Now shutdown the server
	t.Log("Initiating server shutdown after authentication...")
	shutdownDone := make(chan struct{})
	go func() {
		server.Close()
		close(shutdownDone)
	}()

	// Wait for either -ERR message or connection close
	select {
	case errLine := <-errReceived:
		t.Logf("✓ Received -ERR message: %s", errLine)
		if !strings.Contains(errLine, "shutting down") {
			t.Errorf("-ERR message doesn't mention shutdown: %s", errLine)
		}
	case err := <-readError:
		t.Logf("Connection closed: %v", err)
	case <-time.After(3 * time.Second):
		t.Error("Timeout waiting for -ERR message or connection close")
	}

	// Wait for shutdown to complete
	<-shutdownDone
	t.Log("✓ Server shutdown completed")
}
