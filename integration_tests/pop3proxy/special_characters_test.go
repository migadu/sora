//go:build integration

package pop3proxy_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestPOP3ProxySpecialCharacterPasswords tests authentication with passwords containing
// special characters that require RFC 3501 escaping (backslash and double-quote).
// This is a regression test for the bug where passwords with backslash or quotes failed.
func TestPOP3ProxySpecialCharacterPasswords(t *testing.T) {
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
			// Create backend POP3 server
			backendServer, account := common.SetupPOP3ServerWithMaster(t)
			defer backendServer.Close()

			// Update account password to the test password
			if err := backendServer.ResilientDB.UpdatePasswordWithRetry(
				context.Background(),
				account.Email,
				tc.password,
			); err != nil {
				t.Fatalf("Failed to update account password: %v", err)
			}

			// Set up POP3 proxy
			proxyAddress := common.GetRandomAddress(t)
			proxy := setupPOP3ProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
			defer proxy.Close()

			// Wait for servers to be ready
			time.Sleep(300 * time.Millisecond)

			// Test authentication through proxy
			t.Logf("Testing %s: %s", tc.description, tc.password)
			testPOP3Login(t, proxyAddress, account.Email, tc.password)
		})
	}
}

// TestPOP3ProxyUSERPASSParsing tests the USER/PASS command parsing with special characters
func TestPOP3ProxyUSERPASSParsing(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server and account
	backendServer, account := common.SetupPOP3ServerWithMaster(t)
	defer backendServer.Close()

	// Set password to a known value with special characters
	testPassword := `my\pass"word`
	if err := backendServer.ResilientDB.UpdatePasswordWithRetry(
		context.Background(),
		account.Email,
		testPassword,
	); err != nil {
		t.Fatalf("Failed to update account password: %v", err)
	}

	// Set up POP3 proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	time.Sleep(300 * time.Millisecond)

	// Test with USER/PASS commands (POP3 doesn't use quoting like IMAP)
	testPOP3Login(t, proxyAddress, account.Email, testPassword)
}

// TestPOP3ProxyAUTHPLAIN tests AUTH PLAIN with special character passwords
func TestPOP3ProxyAUTHPLAIN(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server
	backendServer, account := common.SetupPOP3ServerWithMaster(t)
	defer backendServer.Close()

	// Set password with special characters
	testPassword := `test\pass"word`
	if err := backendServer.ResilientDB.UpdatePasswordWithRetry(
		context.Background(),
		account.Email,
		testPassword,
	); err != nil {
		t.Fatalf("Failed to update account password: %v", err)
	}

	// Set up POP3 proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	time.Sleep(300 * time.Millisecond)

	// Test AUTH PLAIN (which uses base64 encoding, so no escaping needed)
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
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
	saslPlain := fmt.Sprintf("\x00%s\x00%s", account.Email, testPassword)
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
	} else {
		t.Logf("✓ AUTH PLAIN succeeded with special character password")
	}
}

// testPOP3Login performs a POP3 USER/PASS login to test authentication
func testPOP3Login(t *testing.T, addr, email, password string) {
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
	t.Logf("Received greeting: %s", strings.TrimSpace(greeting))

	// Send USER command
	userCmd := fmt.Sprintf("USER %s\r\n", email)
	t.Logf("Sending: USER %s", email)
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
	t.Logf("USER response: %s", strings.TrimSpace(userResp))

	// Send PASS command
	// Note: POP3 doesn't use IMAP-style quoting, so we send the password as-is
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

	t.Logf("✓ Login succeeded with password: %q", password)
	t.Logf("PASS response: %s", strings.TrimSpace(passResp))
}
