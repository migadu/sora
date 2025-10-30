//go:build integration

package imap_test

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

// TestIMAPBackendSpecialCharacterPasswords tests IMAP backend authentication with passwords
// containing special characters that require RFC 3501 escaping (backslash and double-quote).
// This is a regression test for the bug where passwords with backslash or quotes failed.
//
// Note: IMAP backend uses go-imap/v2 library which properly handles RFC 3501 escaping,
// so these tests verify that the library continues to work correctly.
func TestIMAPBackendSpecialCharacterPasswords(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	testCases := []struct {
		name            string
		password        string
		escapedPassword string // How it should be sent in IMAP protocol
		description     string
	}{
		{
			name:            "password_with_backslash",
			password:        `foo\bar`,
			escapedPassword: `foo\\bar`,
			description:     "Password containing literal backslash",
		},
		{
			name:            "password_with_quote",
			password:        `foo"bar`,
			escapedPassword: `foo\"bar`,
			description:     "Password containing literal double-quote",
		},
		{
			name:            "password_with_backslash_and_quote",
			password:        `foo\"bar`,
			escapedPassword: `foo\\\"bar`,
			description:     "Password containing backslash followed by quote",
		},
		{
			name:            "password_with_multiple_backslashes",
			password:        `foo\\bar`,
			escapedPassword: `foo\\\\bar`,
			description:     "Password containing two backslashes",
		},
		{
			name:            "password_starting_with_backslash",
			password:        `\password`,
			escapedPassword: `\\password`,
			description:     "Password starting with backslash",
		},
		{
			name:            "password_ending_with_backslash",
			password:        `password\`,
			escapedPassword: `password\\`,
			description:     "Password ending with backslash",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create IMAP backend server
			server, account := common.SetupIMAPServer(t)
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

			// Test authentication via LOGIN command
			t.Logf("Testing %s: %s", tc.description, tc.password)
			testIMAPLogin(t, server.Address, account.Email, tc.password, tc.escapedPassword)

			// Test authentication via AUTHENTICATE PLAIN
			testIMAPAuthPlain(t, server.Address, account.Email, tc.password)
		})
	}
}

// testIMAPLogin tests LOGIN command with properly escaped password
func testIMAPLogin(t *testing.T, addr, email, password, escapedPassword string) {
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
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("Invalid greeting: %s", greeting)
	}

	// Send LOGIN with properly escaped password
	loginCmd := fmt.Sprintf("A001 LOGIN \"%s\" \"%s\"\r\n", email, escapedPassword)
	t.Logf("Sending: A001 LOGIN \"%s\" \"%s\"", email, escapedPassword)
	_, err = conn.Write([]byte(loginCmd))
	if err != nil {
		t.Fatalf("Failed to send LOGIN: %v", err)
	}

	// Read response
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if !strings.Contains(response, "A001 OK") {
		t.Errorf("Login failed with password containing special characters")
		t.Errorf("Password: %q (escaped as: %q)", password, escapedPassword)
		t.Errorf("Response: %s", response)
		t.FailNow()
	}

	t.Logf("✓ LOGIN succeeded with password: %q", password)
}

// testIMAPAuthPlain tests AUTHENTICATE PLAIN with special character passwords
func testIMAPAuthPlain(t *testing.T, addr, email, password string) {
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
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("Invalid greeting: %s", greeting)
	}

	// Prepare SASL PLAIN response: \0username\0password
	saslPlain := fmt.Sprintf("\x00%s\x00%s", email, password)
	encoded := base64.StdEncoding.EncodeToString([]byte(saslPlain))

	// Send AUTHENTICATE PLAIN with initial response
	cmd := fmt.Sprintf("A001 AUTHENTICATE PLAIN %s\r\n", encoded)
	_, err = conn.Write([]byte(cmd))
	if err != nil {
		t.Fatalf("Failed to send AUTHENTICATE: %v", err)
	}

	// Read response
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if !strings.Contains(response, "A001 OK") {
		t.Errorf("AUTHENTICATE PLAIN failed with special character password: %s", response)
		t.FailNow()
	}

	t.Logf("✓ AUTHENTICATE PLAIN succeeded with password: %q", password)
}
