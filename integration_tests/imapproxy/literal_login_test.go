//go:build integration

package imapproxy_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAPProxyLiteralLogin tests LOGIN command with IMAP literals for username and password
// This tests the RFC 3501 literal syntax: {size}\r\ndata
func TestIMAPProxyLiteralLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	testCases := []struct {
		name        string
		email       string
		password    string
		description string
	}{
		{
			name:        "simple_credentials",
			email:       "test.user@example.com",
			password:    "password",
			description: "Simple username and password",
		},
		{
			name:        "long_username",
			email:       "very.long.username.for.testing@example.com",
			password:    "testpass123",
			description: "Long email address",
		},
		{
			name:        "special_chars_in_password",
			email:       "user@example.com",
			password:    `p@ss\"w0rd\`,
			description: "Password with special characters (backslash, quote, etc)",
		},
		{
			name:        "unicode_password",
			email:       "user@example.com",
			password:    "пароль123",
			description: "Password with unicode characters",
		},
		{
			name:        "spaces_in_password",
			email:       "user@example.com",
			password:    "my password with spaces",
			description: "Password with spaces",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create backend IMAP server with PROXY protocol support
			backendServer, account := common.SetupIMAPServerWithPROXY(t)
			defer backendServer.Close()

			// Use the account's email (we can't change it easily)
			// Just update the password to test value
			testEmail := account.Email
			hashedPassword, err := db.GenerateBcryptHash(tc.password)
			if err != nil {
				t.Fatalf("Failed to hash password: %v", err)
			}
			if err := backendServer.ResilientDB.UpdatePasswordWithRetry(
				context.Background(),
				testEmail,
				hashedPassword,
			); err != nil {
				t.Fatalf("Failed to update account password: %v", err)
			}

			// Set up IMAP proxy
			proxyAddress := common.GetRandomAddress(t)
			proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
			defer proxy.Close()

			// Wait for servers to be ready
			time.Sleep(300 * time.Millisecond)

			// Test 1: Both username and password as literals
			t.Run("both_literals", func(t *testing.T) {
				testLiteralLogin(t, proxyAddress, testEmail, tc.password, true, true)
			})

			// Test 2: Username as literal, password as quoted string
			t.Run("username_literal_password_quoted", func(t *testing.T) {
				testLiteralLogin(t, proxyAddress, testEmail, tc.password, true, false)
			})

			// Test 3: Username as quoted string, password as literal
			t.Run("username_quoted_password_literal", func(t *testing.T) {
				testLiteralLogin(t, proxyAddress, testEmail, tc.password, false, true)
			})
		})
	}
}

// TestIMAPProxyLiteralLoginEdgeCases tests edge cases for literal LOGIN
func TestIMAPProxyLiteralLoginEdgeCases(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server with PROXY protocol support
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Set up IMAP proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	time.Sleep(300 * time.Millisecond)

	testCases := []struct {
		name          string
		sendFunc      func(conn net.Conn, reader *bufio.Reader) error
		shouldSucceed bool
		description   string
	}{
		{
			name: "zero_length_literal",
			sendFunc: func(conn net.Conn, reader *bufio.Reader) error {
				// Send LOGIN with zero-length username literal
				if _, err := conn.Write([]byte("A001 LOGIN {0}\r\n")); err != nil {
					return err
				}
				// Read continuation
				if line, err := reader.ReadString('\n'); err != nil {
					return err
				} else if !strings.HasPrefix(line, "+") {
					return fmt.Errorf("expected continuation, got: %s", line)
				}
				// Send empty username and password
				if _, err := conn.Write([]byte(fmt.Sprintf(" {%d}\r\n", len(account.Password)))); err != nil {
					return err
				}
				// Read continuation
				if line, err := reader.ReadString('\n'); err != nil {
					return err
				} else if !strings.HasPrefix(line, "+") {
					return fmt.Errorf("expected continuation, got: %s", line)
				}
				// Send password
				if _, err := conn.Write([]byte(account.Password + "\r\n")); err != nil {
					return err
				}
				return nil
			},
			shouldSucceed: false,
			description:   "Zero-length username literal should fail",
		},
		{
			name: "invalid_literal_format",
			sendFunc: func(conn net.Conn, reader *bufio.Reader) error {
				// Send LOGIN with invalid literal (missing closing brace)
				if _, err := conn.Write([]byte("A001 LOGIN {10\r\n")); err != nil {
					return err
				}
				return nil
			},
			shouldSucceed: false,
			description:   "Invalid literal format should fail",
		},
		{
			name: "literal_size_mismatch",
			sendFunc: func(conn net.Conn, reader *bufio.Reader) error {
				// Send LOGIN with literal size 10 but only send 5 bytes
				if _, err := conn.Write([]byte("A001 LOGIN {10}\r\n")); err != nil {
					return err
				}
				// Read continuation
				if line, err := reader.ReadString('\n'); err != nil {
					return err
				} else if !strings.HasPrefix(line, "+") {
					return fmt.Errorf("expected continuation, got: %s", line)
				}
				// Send only 5 bytes (mismatch)
				if _, err := conn.Write([]byte("short")); err != nil {
					return err
				}
				// Server will be waiting for 5 more bytes, connection should timeout or close
				time.Sleep(2 * time.Second)
				return nil
			},
			shouldSucceed: false,
			description:   "Literal size mismatch should cause connection to close or timeout",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", proxyAddress)
			if err != nil {
				t.Fatalf("Failed to connect to proxy: %v", err)
			}
			defer conn.Close()

			// Set a reasonable timeout for the test
			conn.SetDeadline(time.Now().Add(5 * time.Second))

			reader := bufio.NewReader(conn)

			// Read greeting
			greeting, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Failed to read greeting: %v", err)
			}
			if !strings.HasPrefix(greeting, "* OK") {
				t.Fatalf("Invalid greeting: %s", greeting)
			}

			t.Logf("Testing: %s", tc.description)

			// Execute test-specific send function
			if err := tc.sendFunc(conn, reader); err != nil {
				if !tc.shouldSucceed {
					t.Logf("✓ Failed as expected: %v", err)
					return
				}
				t.Fatalf("Send failed: %v", err)
			}

			// Try to read response
			response, err := reader.ReadString('\n')
			if err != nil {
				if !tc.shouldSucceed && (err == io.EOF || strings.Contains(err.Error(), "timeout")) {
					t.Logf("✓ Connection closed/timeout as expected")
					return
				}
				t.Fatalf("Failed to read response: %v", err)
			}

			if tc.shouldSucceed {
				if !strings.Contains(response, "A001 OK") {
					t.Errorf("Expected success but got: %s", response)
				} else {
					t.Logf("✓ Login succeeded as expected")
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

// escapeForIMAP escapes special characters for IMAP quoted strings per RFC 3501.
// Backslashes and double-quotes must be escaped.
func escapeForIMAP(s string) string {
	var result strings.Builder
	for _, c := range s {
		if c == '\\' || c == '"' {
			result.WriteRune('\\')
		}
		result.WriteRune(c)
	}
	return result.String()
}

// testLiteralLogin performs a LOGIN with literal syntax
func testLiteralLogin(t *testing.T, addr, email, password string, usernameLiteral, passwordLiteral bool) {
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

	// Build and send LOGIN command
	var loginCmd string
	if usernameLiteral {
		loginCmd = fmt.Sprintf("A001 LOGIN {%d}\r\n", len(email))
		t.Logf("Sending: A001 LOGIN {%d}", len(email))
	} else {
		loginCmd = fmt.Sprintf("A001 LOGIN \"%s\"", email)
		t.Logf("Sending: A001 LOGIN \"%s\" ...", email)
	}

	_, err = conn.Write([]byte(loginCmd))
	if err != nil {
		t.Fatalf("Failed to send LOGIN: %v", err)
	}

	// If username is literal, read continuation and send username
	if usernameLiteral {
		continuation, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read continuation: %v", err)
		}
		if !strings.HasPrefix(continuation, "+") {
			t.Fatalf("Expected continuation '+', got: %s", continuation)
		}
		t.Logf("Received continuation: %s", strings.TrimSpace(continuation))

		// Send username data
		_, err = conn.Write([]byte(email))
		if err != nil {
			t.Fatalf("Failed to send username data: %v", err)
		}
		t.Logf("Sent username: %s", email)

		// Send space and password part
		if passwordLiteral {
			passwordCmd := fmt.Sprintf(" {%d}\r\n", len(password))
			_, err = conn.Write([]byte(passwordCmd))
			if err != nil {
				t.Fatalf("Failed to send password literal indicator: %v", err)
			}
			t.Logf("Sent: {%d}", len(password))
		} else {
			// Password must be escaped for IMAP quoted string syntax
			escapedPassword := escapeForIMAP(password)
			passwordCmd := fmt.Sprintf(" \"%s\"\r\n", escapedPassword)
			_, err = conn.Write([]byte(passwordCmd))
			if err != nil {
				t.Fatalf("Failed to send password: %v", err)
			}
			t.Logf("Sent password (quoted, escaped)")
		}
	} else if passwordLiteral {
		// Username was quoted, password is literal
		passwordCmd := fmt.Sprintf(" {%d}\r\n", len(password))
		_, err = conn.Write([]byte(passwordCmd))
		if err != nil {
			t.Fatalf("Failed to send password literal indicator: %v", err)
		}
		t.Logf("Sent: {%d}", len(password))
	} else {
		// Both quoted (should not reach here in this test)
		t.Fatal("Unexpected: both quoted in literal login test")
	}

	// If password is literal, read continuation and send password
	if passwordLiteral {
		continuation, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read continuation for password: %v", err)
		}
		if !strings.HasPrefix(continuation, "+") {
			t.Fatalf("Expected continuation '+', got: %s", continuation)
		}
		t.Logf("Received continuation: %s", strings.TrimSpace(continuation))

		// Send password data followed by CRLF
		_, err = conn.Write([]byte(password + "\r\n"))
		if err != nil {
			t.Fatalf("Failed to send password data: %v", err)
		}
		t.Logf("Sent password")
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
		t.Errorf("Login failed with literal syntax")
		t.Errorf("Email: %q, Password: %q", email, password)
		t.Errorf("Response: %s", finalResponse)
		for i, resp := range responses {
			t.Errorf("  Response line %d: %s", i+1, strings.TrimSpace(resp))
		}
		t.FailNow()
	}

	t.Logf("✓ Login succeeded with literal syntax")
}
