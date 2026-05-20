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

// TestPOP3_LineLengthLimit verifies that POP3 server enforces line length limits (RFC 1939 §3)
func TestPOP3_LineLengthLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)
	defer server.Close()

	t.Run("command within limit", func(t *testing.T) {
		conn, err := net.Dial("tcp", server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)

		// Read greeting
		reader.ReadString('\n')

		// Send CAPA command (well within limit)
		fmt.Fprintf(conn, "CAPA\r\n")
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "+OK") {
			t.Errorf("Expected +OK response, got: %s", line)
		}

		// Read capability list
		for {
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if line == "." {
				break
			}
		}
	})

	t.Run("command at limit", func(t *testing.T) {
		conn, err := net.Dial("tcp", server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)

		// Read greeting
		reader.ReadString('\n')

		// Send USER command with a very long username (but within 1024 bytes)
		// Format: "USER <username>\r\n" = 5 + len(username) + 2 = 1024 max
		// So username can be up to 1017 bytes
		longUser := strings.Repeat("A", 1013) // "USER " (5) + 1013 + "\r\n" (2) = 1020 bytes
		fmt.Fprintf(conn, "USER %s\r\n", longUser)

		// Should get a response (even if -ERR for invalid user)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			t.Error("Expected response for command at limit, got empty")
		}
		// We expect either +OK or -ERR, but not connection close
	})

	t.Run("command exceeds limit", func(t *testing.T) {
		conn, err := net.Dial("tcp", server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)

		// Read greeting
		reader.ReadString('\n')

		// Send USER command exceeding 1024 bytes
		veryLongUser := strings.Repeat("X", 1025) // Exceeds limit
		fmt.Fprintf(conn, "USER %s\r\n", veryLongUser)

		// Should get -ERR line too long and connection close
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil {
			// Connection might be closed immediately
			t.Logf("Connection closed (expected): %v", err)
			return
		}
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "-ERR") || !strings.Contains(strings.ToLower(line), "line too long") {
			t.Errorf("Expected '-ERR Line too long', got: %s", line)
		}

		// Connection should be closed after this
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = reader.ReadString('\n')
		if err == nil {
			t.Error("Expected connection to be closed after line too long error")
		}
	})

	t.Run("massive line without newline", func(t *testing.T) {
		conn, err := net.Dial("tcp", server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)

		// Read greeting
		reader.ReadString('\n')

		// Send very long data without newline
		massiveData := strings.Repeat("Z", 100000) // 100KB without \n
		fmt.Fprintf(conn, "%s", massiveData)

		// Server should eventually close connection due to line length limit
		// or timeout
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))

		// Try to read response
		line, err := reader.ReadString('\n')
		if err != nil {
			// Expected - connection should be closed
			t.Logf("Connection closed as expected: %v", err)
			return
		}

		// If we get a response, it should be an error
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "-ERR") {
			t.Errorf("Expected error response, got: %s", line)
		}
	})

	// Avoid unused variable warning
	_ = account
}
