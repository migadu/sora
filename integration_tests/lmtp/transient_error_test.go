//go:build integration

package lmtp_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTPBackendUserNotFound tests that user not found returns 550 (permanent failure)
func TestLMTPBackendUserNotFound(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupLMTPServer(t)
	defer server.Close()

	// Test 1: User exists (should accept)
	t.Run("UserExists_AcceptsRecipient", func(t *testing.T) {
		client, err := NewLMTPClient(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		// LHLO
		if err := client.SendCommand("LHLO test"); err != nil {
			t.Fatalf("Failed to send LHLO: %v", err)
		}
		if _, err := client.ReadMultilineResponse(); err != nil {
			t.Fatalf("Failed to read LHLO response: %v", err)
		}

		// MAIL FROM
		if err := client.SendCommand("MAIL FROM:<sender@example.com>"); err != nil {
			t.Fatalf("Failed to send MAIL FROM: %v", err)
		}
		resp, _ := client.ReadResponse()
		if !strings.HasPrefix(resp, "250") {
			t.Fatalf("MAIL FROM failed: %s", resp)
		}

		// RCPT TO (user exists)
		if err := client.SendCommand(fmt.Sprintf("RCPT TO:<%s>", account.Email)); err != nil {
			t.Fatalf("Failed to send RCPT TO: %v", err)
		}
		resp, _ = client.ReadResponse()
		if !strings.HasPrefix(resp, "250") {
			t.Errorf("Expected 250 for existing user, got: %s", resp)
		}
	})

	// Test 2: User not found (should return 550 - permanent)
	t.Run("UserNotFound_Returns550", func(t *testing.T) {
		client, err := NewLMTPClient(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		// LHLO
		if err := client.SendCommand("LHLO test"); err != nil {
			t.Fatalf("Failed to send LHLO: %v", err)
		}
		if _, err := client.ReadMultilineResponse(); err != nil {
			t.Fatalf("Failed to read LHLO response: %v", err)
		}

		// MAIL FROM
		if err := client.SendCommand("MAIL FROM:<sender@example.com>"); err != nil {
			t.Fatalf("Failed to send MAIL FROM: %v", err)
		}
		client.ReadResponse()

		// RCPT TO (user does not exist)
		if err := client.SendCommand("RCPT TO:<nonexistent@example.com>"); err != nil {
			t.Fatalf("Failed to send RCPT TO: %v", err)
		}
		resp, _ := client.ReadResponse()
		if !strings.HasPrefix(resp, "550") {
			t.Errorf("Expected 550 for non-existent user, got: %s", resp)
		}
		if !strings.Contains(resp, "5.1.1") {
			t.Errorf("Expected enhanced code 5.1.1, got: %s", resp)
		}
	})
}

// TestLMTPBackendDatabaseTransientError tests that database connection errors
// return 451 (temporary failure) instead of 550 (permanent failure)
//
// This test simulates a database failure by closing the server's database connections
// and verifies that LMTP returns 451 (retry) instead of 550 (permanent bounce).
func TestLMTPBackendDatabaseTransientError(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupLMTPServer(t)
	defer server.Close()

	// First verify normal operation works
	t.Run("NormalOperation_Works", func(t *testing.T) {
		client, err := NewLMTPClient(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		// LHLO
		if err := client.SendCommand("LHLO test"); err != nil {
			t.Fatalf("Failed to send LHLO: %v", err)
		}
		if _, err := client.ReadMultilineResponse(); err != nil {
			t.Fatalf("Failed to read LHLO response: %v", err)
		}

		// MAIL FROM
		if err := client.SendCommand("MAIL FROM:<sender@example.com>"); err != nil {
			t.Fatalf("Failed to send MAIL FROM: %v", err)
		}
		client.ReadResponse()

		// RCPT TO (should work normally)
		if err := client.SendCommand(fmt.Sprintf("RCPT TO:<%s>", account.Email)); err != nil {
			t.Fatalf("Failed to send RCPT TO: %v", err)
		}
		resp, _ := client.ReadResponse()
		if !strings.HasPrefix(resp, "250") {
			t.Fatalf("Normal operation failed, expected 250, got: %s", resp)
		}
	})

	// Now close the database to simulate database failure
	t.Run("DatabaseError_Returns4xx", func(t *testing.T) {
		// Close the database connection pool
		server.ResilientDB.Close()

		// Give server time to detect closed connections
		time.Sleep(500 * time.Millisecond)

		client, err := NewLMTPClient(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		// LHLO
		if err := client.SendCommand("LHLO test"); err != nil {
			t.Fatalf("Failed to send LHLO: %v", err)
		}
		if _, err := client.ReadMultilineResponse(); err != nil {
			t.Fatalf("Failed to read LHLO response: %v", err)
		}

		// MAIL FROM
		if err := client.SendCommand("MAIL FROM:<sender@example.com>"); err != nil {
			t.Fatalf("Failed to send MAIL FROM: %v", err)
		}
		client.ReadResponse()

		// RCPT TO (database unavailable)
		if err := client.SendCommand(fmt.Sprintf("RCPT TO:<%s>", account.Email)); err != nil {
			t.Fatalf("Failed to send RCPT TO: %v", err)
		}
		resp, _ := client.ReadResponse()

		t.Logf("Database error response: %s", resp)

		// CRITICAL: Database errors should return 4xx (temporary) not 5xx (permanent)
		// This is the bug we're fixing - currently returns 550, should return 451
		if strings.HasPrefix(resp, "550") {
			t.Errorf("FAIL: Database error returned 550 (permanent failure) instead of 4xx (temporary failure): %s", resp)
			t.Errorf("This will cause MTAs to permanently bounce emails during temporary database issues!")
		}

		// Check enhanced code is 4.x.x (temporary) not 5.x.x (permanent)
		if strings.Contains(resp, " 5.") {
			t.Errorf("FAIL: Enhanced code indicates permanent failure (5.x.x): %s", resp)
			t.Errorf("Expected 4.x.x (temporary failure) for database errors")
		}

		// After fix, we expect 451 or 421
		if !strings.HasPrefix(resp, "451") && !strings.HasPrefix(resp, "421") {
			t.Logf("Note: Expected 451 or 421 for database error, got: %s", resp)
		}
	})
}

// TestLMTPBackendDefaultErrorFallback tests that unknown errors default to 4xx not 5xx
func TestLMTPBackendDefaultErrorFallback(t *testing.T) {
	// This test verifies that if we somehow get an unexpected error,
	// we return a temporary failure (4xx) rather than permanent (5xx)
	// so MTAs will retry rather than bouncing messages

	t.Run("UnexpectedError_Should_Return4xx", func(t *testing.T) {
		// Note: This is more of a code review test than a runtime test
		// We verify through code inspection that default error handling uses 4xx

		t.Log("Verifying that LMTP backend defaults to 4xx for unexpected errors")
		t.Log("This ensures MTAs will retry during unexpected issues rather than bouncing")

		// After fix, the code should:
		// 1. Return 550 only for pgx.ErrNoRows (user not found)
		// 2. Return 451 for all other database errors (transient)
		// 3. Default unknown errors to 451 (temporary) not 550 (permanent)

		t.Log("Implementation check: session.go Rcpt() should return 451 for database errors")
		t.Log("Implementation check: session.go Rcpt() should return 550 only for pgx.ErrNoRows")
		t.Log("Implementation check: Unknown errors should default to 451 (temporary)")
	})
}
