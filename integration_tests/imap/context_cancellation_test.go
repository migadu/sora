//go:build integration

package imap_test

import (
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_ContextCancellationDuringAuth tests that context cancellation
// during authentication (server shutdown) returns UNAVAILABLE instead of
// AUTHENTICATIONFAILED, preventing clients from being incorrectly told
// their password is wrong and avoiding rate limiting penalties.
func TestIMAP_ContextCancellationDuringAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	// Don't defer server.Close() - we'll close it manually during auth

	// First, verify normal login works
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}

	if err := c1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Initial login failed: %v", err)
	}
	t.Log("✓ Initial login successful")
	c1.Logout()

	// Now test authentication during server shutdown
	// We'll create a new connection and attempt login while closing the server
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server for shutdown test: %v", err)
	}
	defer c2.Logout()

	// Start login in a goroutine
	loginErrChan := make(chan error, 1)
	go func() {
		// Give the server a moment to start processing
		time.Sleep(10 * time.Millisecond)
		loginErrChan <- c2.Login(account.Email, account.Password).Wait()
	}()

	// Close the server while authentication is in progress or about to start
	time.Sleep(5 * time.Millisecond)
	server.Close()
	t.Log("✓ Server closed during authentication")

	// Wait for login to complete
	loginErr := <-loginErrChan

	// The login should fail, but we need to check the error message
	if loginErr == nil {
		t.Fatal("Expected login to fail during server shutdown, but it succeeded")
	}

	t.Logf("Login error: %v", loginErr)

	// Check that the error contains UNAVAILABLE, not AUTHENTICATIONFAILED
	errStr := loginErr.Error()
	if strings.Contains(errStr, "UNAVAILABLE") || strings.Contains(errStr, "shutting down") {
		t.Logf("✓ Correctly received UNAVAILABLE response (or connection closed)")
	} else if strings.Contains(errStr, "AUTHENTICATIONFAILED") || strings.Contains(errStr, "Invalid address or password") {
		t.Errorf("FAIL: Received AUTHENTICATIONFAILED instead of UNAVAILABLE during shutdown")
		t.Errorf("This will cause clients to prompt for password and penalize rate limiting")
		t.Errorf("Error was: %v", loginErr)
	} else if strings.Contains(errStr, "connection") || strings.Contains(errStr, "closed") || strings.Contains(errStr, "EOF") {
		// Connection might be closed before the response is sent - this is acceptable
		t.Logf("✓ Connection closed before response (acceptable during shutdown)")
	} else {
		t.Logf("⚠ Unexpected error type (but not AUTHENTICATIONFAILED): %v", loginErr)
	}
}

// TestIMAP_ContextCancellationDuringDBAuth tests context cancellation
// specifically during database authentication by using a cancelled context.
// This simulates what happens when the server context is cancelled during
// a database operation.
func TestIMAP_ContextCancellationDuringDBAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// First verify normal login works
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}

	if err := c1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Initial login failed: %v", err)
	}
	t.Log("✓ Initial login successful")
	c1.Logout()

	// Now simulate multiple rapid connections during shutdown
	// Some should hit the context cancellation path in the database
	const numConnections = 5
	errChan := make(chan error, numConnections)

	// Close server after a short delay
	go func() {
		time.Sleep(20 * time.Millisecond)
		server.Close()
		t.Log("✓ Server closed")
	}()

	// Attempt multiple logins concurrently
	for i := 0; i < numConnections; i++ {
		go func(idx int) {
			c, err := imapclient.DialInsecure(server.Address, nil)
			if err != nil {
				errChan <- err
				return
			}
			defer c.Logout()

			// Stagger the login attempts slightly
			time.Sleep(time.Duration(idx*5) * time.Millisecond)
			err = c.Login(account.Email, account.Password).Wait()
			errChan <- err
		}(i)
	}

	// Collect results
	authFailedCount := 0
	unavailableCount := 0
	successCount := 0
	connectionErrorCount := 0

	for i := 0; i < numConnections; i++ {
		err := <-errChan
		if err == nil {
			successCount++
		} else {
			errStr := err.Error()
			switch {
			case strings.Contains(errStr, "AUTHENTICATIONFAILED") || strings.Contains(errStr, "Invalid address or password"):
				authFailedCount++
				t.Errorf("Connection %d: Got AUTHENTICATIONFAILED during shutdown: %v", i, err)
			case strings.Contains(errStr, "UNAVAILABLE") || strings.Contains(errStr, "shutting down"):
				unavailableCount++
				t.Logf("Connection %d: ✓ Got UNAVAILABLE: %v", i, err)
			case strings.Contains(errStr, "connection") || strings.Contains(errStr, "closed") || strings.Contains(errStr, "EOF"):
				connectionErrorCount++
				t.Logf("Connection %d: Connection error (acceptable): %v", i, err)
			default:
				t.Logf("Connection %d: Other error: %v", i, err)
			}
		}
	}

	t.Logf("Results: Success=%d, UNAVAILABLE=%d, ConnectionError=%d, AUTHENTICATIONFAILED=%d",
		successCount, unavailableCount, connectionErrorCount, authFailedCount)

	// The critical check: we should NEVER get AUTHENTICATIONFAILED during shutdown
	if authFailedCount > 0 {
		t.Errorf("FAIL: %d connections received AUTHENTICATIONFAILED during shutdown", authFailedCount)
		t.Errorf("This causes clients to prompt for password and penalizes rate limiting")
	} else {
		t.Log("✓ No AUTHENTICATIONFAILED responses during shutdown")
	}
}

// TestIMAP_NormalAuthFailureStillWorks verifies that legitimate auth failures
// still return AUTHENTICATIONFAILED (not UNAVAILABLE), ensuring our fix doesn't
// break normal error handling.
func TestIMAP_NormalAuthFailureStillWorks(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	// Test wrong password
	err = c.Login(account.Email, "wrong_password").Wait()
	if err == nil {
		t.Fatal("Expected login to fail with wrong password")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "AUTHENTICATIONFAILED") && !strings.Contains(errStr, "Invalid") {
		t.Errorf("Expected AUTHENTICATIONFAILED for wrong password, got: %v", err)
	} else {
		t.Logf("✓ Wrong password correctly returns AUTHENTICATIONFAILED: %v", err)
	}

	// Test non-existent user
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c2.Logout()

	err = c2.Login("nonexistent@example.com", "password").Wait()
	if err == nil {
		t.Fatal("Expected login to fail for non-existent user")
	}

	errStr = err.Error()
	if !strings.Contains(errStr, "AUTHENTICATIONFAILED") && !strings.Contains(errStr, "Invalid") {
		t.Errorf("Expected AUTHENTICATIONFAILED for non-existent user, got: %v", err)
	} else {
		t.Logf("✓ Non-existent user correctly returns AUTHENTICATIONFAILED: %v", err)
	}
}
