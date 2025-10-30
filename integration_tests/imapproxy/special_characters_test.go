//go:build integration

package imapproxy_test

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

// TestIMAPProxySpecialCharacterPasswords tests authentication with passwords containing
// special characters that require RFC 3501 escaping (backslash and double-quote).
// This is a regression test for the bug where passwords with backslash or quotes failed.
func TestIMAPProxySpecialCharacterPasswords(t *testing.T) {
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
			name:            "password_with_multiple_quotes",
			password:        `foo"bar"baz`,
			escapedPassword: `foo\"bar\"baz`,
			description:     "Password containing multiple quotes",
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
		{
			name:            "complex_password",
			password:        `p@ss\"w0rd\`,
			escapedPassword: `p@ss\\\"w0rd\\`,
			description:     "Complex password with mixed special characters",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create backend IMAP server
			backendServer, account := common.SetupIMAPServerWithMaster(t)
			defer backendServer.Close()

			// Update account password to the test password
			if err := backendServer.ResilientDB.UpdatePasswordWithRetry(
				context.Background(),
				account.Email,
				tc.password,
			); err != nil {
				t.Fatalf("Failed to update account password: %v", err)
			}

			// Set up IMAP proxy
			proxyAddress := common.GetRandomAddress(t)
			proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
			defer proxy.Close()

			// Wait for servers to be ready
			time.Sleep(300 * time.Millisecond)

			// Test authentication through proxy using raw IMAP protocol
			// (Using raw protocol to ensure we're testing the actual parsing)
			t.Logf("Testing %s: %s", tc.description, tc.password)
			testRawIMAPLogin(t, proxyAddress, account.Email, tc.password, tc.escapedPassword)
		})
	}
}

// TestIMAPProxyLOGINCommandParsing specifically tests the LOGIN command parsing
// with various quoting scenarios to ensure RFC 3501 compliance.
func TestIMAPProxyLOGINCommandParsing(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server and account
	backendServer, account := common.SetupIMAPServerWithMaster(t)
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

	// Set up IMAP proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	time.Sleep(300 * time.Millisecond)

	testCases := []struct {
		name          string
		command       string
		shouldSucceed bool
		description   string
	}{
		{
			name:          "both_quoted_correct_escaping",
			command:       fmt.Sprintf(`A001 LOGIN "%s" "my\\pass\"word"`, account.Email),
			shouldSucceed: true,
			description:   "Both arguments quoted with correct escaping",
		},
		{
			name:          "email_unquoted_password_quoted",
			command:       fmt.Sprintf(`A001 LOGIN %s "my\\pass\"word"`, account.Email),
			shouldSucceed: true,
			description:   "Email unquoted, password quoted with escaping",
		},
		{
			name:          "incorrect_escaping_should_fail",
			command:       fmt.Sprintf(`A001 LOGIN "%s" "my\pass"word"`, account.Email),
			shouldSucceed: false,
			description:   "Incorrect escaping (unescaped quote in middle)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
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
			if !strings.HasPrefix(greeting, "* OK") {
				t.Fatalf("Invalid greeting: %s", greeting)
			}

			// Send LOGIN command
			t.Logf("Sending: %s", tc.description)
			_, err = conn.Write([]byte(tc.command + "\r\n"))
			if err != nil {
				t.Fatalf("Failed to send LOGIN: %v", err)
			}

			// Read response
			response, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Failed to read response: %v", err)
			}

			if tc.shouldSucceed {
				if !strings.Contains(response, "A001 OK") {
					t.Errorf("Expected success but got: %s", response)
				} else {
					t.Logf("✓ Login succeeded as expected: %s", strings.TrimSpace(response))
				}
			} else {
				if strings.Contains(response, "A001 OK") {
					t.Errorf("Expected failure but login succeeded: %s", response)
				} else {
					t.Logf("✓ Login failed as expected: %s", strings.TrimSpace(response))
				}
			}
		})
	}
}

// TestIMAPProxyAUTHENTICATEPLAIN tests AUTHENTICATE PLAIN with special character passwords
func TestIMAPProxyAUTHENTICATEPLAIN(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, account := common.SetupIMAPServerWithMaster(t)
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

	// Set up IMAP proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	time.Sleep(300 * time.Millisecond)

	// Test AUTHENTICATE PLAIN (which uses base64 encoding, so no escaping needed)
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
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("Invalid greeting: %s", greeting)
	}

	// Prepare SASL PLAIN response: \0username\0password
	saslPlain := fmt.Sprintf("\x00%s\x00%s", account.Email, testPassword)
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
	} else {
		t.Logf("✓ AUTHENTICATE PLAIN succeeded with special character password")
	}
}

// testRawIMAPLogin performs a raw IMAP LOGIN command to test parsing
func testRawIMAPLogin(t *testing.T, addr, email, password, escapedPassword string) {
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
	t.Logf("Received greeting: %s", strings.TrimSpace(greeting))

	// Send LOGIN with properly escaped password
	loginCmd := fmt.Sprintf("A001 LOGIN \"%s\" \"%s\"\r\n", email, escapedPassword)
	t.Logf("Sending: A001 LOGIN \"%s\" \"%s\"", email, escapedPassword)

	_, err = conn.Write([]byte(loginCmd))
	if err != nil {
		t.Fatalf("Failed to send LOGIN: %v", err)
	}

	// Read response (might be multiple lines)
	var responses []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}
		responses = append(responses, line)

		// Check if this is the tagged response
		if strings.HasPrefix(line, "A001 ") {
			break
		}

		// Safety: don't read forever
		if len(responses) > 10 {
			t.Fatalf("Too many response lines, something is wrong")
		}
	}

	// Check final response
	finalResponse := responses[len(responses)-1]
	t.Logf("Received: %s", strings.TrimSpace(finalResponse))

	if !strings.Contains(finalResponse, "A001 OK") {
		t.Errorf("Login failed with password containing special characters")
		t.Errorf("Password: %q (escaped as: %q)", password, escapedPassword)
		t.Errorf("Response: %s", finalResponse)
		for i, resp := range responses {
			t.Errorf("  Response line %d: %s", i+1, strings.TrimSpace(resp))
		}
		t.FailNow()
	}

	t.Logf("✓ Login succeeded with password: %q", password)
}
