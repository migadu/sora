//go:build integration

package pop3_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// TestPOP3BackendSpecialCharacterPasswords tests POP3 backend authentication with passwords
// containing special characters that require proper parsing (backslash and double-quote).
// This is a regression test for the bug where the custom parser didn't handle escape sequences.
func TestPOP3BackendSpecialCharacterPasswords(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	testCases := []struct {
		name        string
		password    string
		description string
	}{
		{
			name:        "password_with_backslash",
			password:    `foo\bar`,
			description: "Password containing literal backslash",
		},
		{
			name:        "password_with_quote",
			password:    `foo"bar`,
			description: "Password containing literal double-quote",
		},
		{
			name:        "password_with_backslash_and_quote",
			password:    `foo\"bar`,
			description: "Password containing backslash followed by quote",
		},
		{
			name:        "password_with_multiple_backslashes",
			password:    `foo\\bar`,
			description: "Password containing two backslashes",
		},
		{
			name:        "password_starting_with_backslash",
			password:    `\password`,
			description: "Password starting with backslash",
		},
		{
			name:        "password_ending_with_backslash",
			password:    `password\`,
			description: "Password ending with backslash",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create POP3 backend server
			server, account := common.SetupPOP3Server(t)
			defer server.Close()

			// Update account password to the test password
			hashedPassword, err := db.GenerateBcryptHash(tc.password)
			if err != nil {
				t.Fatalf("Failed to hash password: %v", err)
			}
			if err := server.ResilientDB.UpdatePasswordWithRetry(
				context.Background(),
				account.Email,
				hashedPassword,
			); err != nil {
				t.Fatalf("Failed to update account password: %v", err)
			}

			time.Sleep(100 * time.Millisecond)

			// Test authentication via USER/PASS commands
			t.Logf("Testing %s: %s", tc.description, tc.password)
			testPOP3UserPass(t, server.Address, account.Email, tc.password)

			// Test authentication via AUTH PLAIN
			testPOP3AuthPlain(t, server.Address, account.Email, tc.password)
		})
	}
}

// testPOP3UserPass tests USER/PASS authentication with special character passwords
func testPOP3UserPass(t *testing.T, addr, email, password string) {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("Invalid greeting: %s", greeting)
	}

	// Send USER command
	userCmd := fmt.Sprintf("USER %s\r\n", email)
	_, err = conn.Write([]byte(userCmd))
	if err != nil {
		t.Fatalf("Failed to send USER: %v", err)
	}

	// Read USER response
	userResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}
	if !strings.HasPrefix(userResp, "+OK") {
		t.Fatalf("USER command failed: %s", userResp)
	}

	// Send PASS command
	// Note: POP3 doesn't use IMAP-style quoting, password is sent as-is
	passCmd := fmt.Sprintf("PASS %s\r\n", password)
	t.Logf("Sending: PASS <password>")
	_, err = conn.Write([]byte(passCmd))
	if err != nil {
		t.Fatalf("Failed to send PASS: %v", err)
	}

	// Read PASS response
	passResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}

	if !strings.HasPrefix(passResp, "+OK") {
		t.Errorf("PASS command failed with password containing special characters")
		t.Errorf("Password: %q", password)
		t.Errorf("Response: %s", passResp)
		t.FailNow()
	}

	t.Logf("✓ USER/PASS succeeded with password: %q", password)
}

// testPOP3AuthPlain tests AUTH PLAIN with special character passwords
func testPOP3AuthPlain(t *testing.T, addr, email, password string) {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("Invalid greeting: %s", greeting)
	}

	// Prepare SASL PLAIN response: \0username\0password
	saslPlain := fmt.Sprintf("\x00%s\x00%s", email, password)
	encoded := base64.StdEncoding.EncodeToString([]byte(saslPlain))

	// Send AUTH PLAIN with inline response
	cmd := fmt.Sprintf("AUTH PLAIN %s\r\n", encoded)
	_, err = conn.Write([]byte(cmd))
	if err != nil {
		t.Fatalf("Failed to send AUTH: %v", err)
	}

	// Read response
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if !strings.HasPrefix(response, "+OK") {
		t.Errorf("AUTH PLAIN failed with special character password: %s", response)
		t.FailNow()
	}

	t.Logf("✓ AUTH PLAIN succeeded with password: %q", password)
}
