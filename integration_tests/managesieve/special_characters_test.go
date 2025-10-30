//go:build integration

package managesieve

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

// TestManageSieveSpecialCharacterPasswords tests authentication with passwords containing
// special characters that require RFC 3501 escaping (backslash and double-quote).
// This is a regression test for the bug where passwords with backslash or quotes failed.
func TestManageSieveSpecialCharacterPasswords(t *testing.T) {
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
		{
			name:        "complex_password",
			password:    `p@ss\"w0rd\`,
			description: "Complex password with mixed special characters",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create ManageSieve server
			server, account := common.SetupManageSieveServer(t)
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

			// Wait for server to be ready
			time.Sleep(200 * time.Millisecond)

			// Test authentication
			t.Logf("Testing %s: %s", tc.description, tc.password)
			testManageSieveAuth(t, server.Address, account.Email, tc.password)
		})
	}
}

// TestManageSieveAUTHENTICATEPLAIN tests AUTHENTICATE PLAIN with special character passwords
func TestManageSieveAUTHENTICATEPLAIN(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create ManageSieve server
	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	// Set password with special characters
	testPassword := `test\pass"word`
	hashedPassword, err := db.GenerateBcryptHash(testPassword)
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

	time.Sleep(200 * time.Millisecond)

	// Test AUTH (ManageSieve uses AUTHENTICATE like IMAP)
	testManageSieveAuth(t, server.Address, account.Email, testPassword)
}

// TestManageSieveAuthQuoting tests the AUTHENTICATE command with quoted arguments
func TestManageSieveAuthQuoting(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create ManageSieve server and account
	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	// Set password to a known value with special characters
	testPassword := `my\pass"word`
	hashedPassword, err := db.GenerateBcryptHash(testPassword)
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

	time.Sleep(200 * time.Millisecond)

	testCases := []struct {
		name          string
		authMechanism string
		useQuotes     bool
		shouldSucceed bool
		description   string
	}{
		{
			name:          "quoted_mechanism",
			authMechanism: `"PLAIN"`,
			useQuotes:     true,
			shouldSucceed: true,
			description:   "AUTHENTICATE with quoted mechanism name",
		},
		{
			name:          "unquoted_mechanism",
			authMechanism: "PLAIN",
			useQuotes:     false,
			shouldSucceed: true,
			description:   "AUTHENTICATE with unquoted mechanism name",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", server.Address)
			if err != nil {
				t.Fatalf("Failed to connect: %v", err)
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)

			// Read greeting (capabilities followed by OK)
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					t.Fatalf("Failed to read greeting: %v", err)
				}
				if strings.HasPrefix(strings.TrimSpace(line), "OK") {
					break
				}
			}

			// Prepare SASL PLAIN response: \0username\0password
			saslPlain := fmt.Sprintf("\x00%s\x00%s", account.Email, testPassword)
			encoded := base64.StdEncoding.EncodeToString([]byte(saslPlain))

			// Send AUTHENTICATE command
			cmd := fmt.Sprintf("AUTHENTICATE %s %s\r\n", tc.authMechanism, encoded)
			t.Logf("Sending: %s", tc.description)
			_, err = conn.Write([]byte(cmd))
			if err != nil {
				t.Fatalf("Failed to send AUTHENTICATE: %v", err)
			}

			// Read response
			response, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Failed to read response: %v", err)
			}

			if tc.shouldSucceed {
				if !strings.HasPrefix(strings.TrimSpace(response), "OK") {
					t.Errorf("Expected success but got: %s", response)
				} else {
					t.Logf("✓ Authentication succeeded as expected: %s", strings.TrimSpace(response))
				}
			} else {
				if strings.HasPrefix(strings.TrimSpace(response), "OK") {
					t.Errorf("Expected failure but authentication succeeded: %s", response)
				} else {
					t.Logf("✓ Authentication failed as expected: %s", strings.TrimSpace(response))
				}
			}
		})
	}
}

// testManageSieveAuth performs ManageSieve AUTHENTICATE PLAIN to test authentication
func testManageSieveAuth(t *testing.T, addr, email, password string) {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting (capabilities followed by OK)
	var greetingLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting: %v", err)
		}
		greetingLines = append(greetingLines, line)
		if strings.HasPrefix(strings.TrimSpace(line), "OK") {
			break
		}
	}
	t.Logf("Received greeting (%d lines)", len(greetingLines))

	// Prepare SASL PLAIN response: \0username\0password
	saslPlain := fmt.Sprintf("\x00%s\x00%s", email, password)
	encoded := base64.StdEncoding.EncodeToString([]byte(saslPlain))

	// Send AUTHENTICATE PLAIN with inline response
	cmd := fmt.Sprintf("AUTHENTICATE \"PLAIN\" %s\r\n", encoded)
	t.Logf("Sending: AUTHENTICATE \"PLAIN\" <base64>")
	_, err = conn.Write([]byte(cmd))
	if err != nil {
		t.Fatalf("Failed to send AUTHENTICATE: %v", err)
	}

	// Read response
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	response = strings.TrimSpace(response)
	if !strings.HasPrefix(response, "OK") {
		t.Errorf("Authentication failed with password containing special characters")
		t.Errorf("Password: %q", password)
		t.Errorf("Response: %s", response)
		t.FailNow()
	}

	t.Logf("✓ Authentication succeeded with password: %q", password)
	t.Logf("Response: %s", response)
}
