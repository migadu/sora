//go:build integration

package managesieve_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestManageSieve_LineLengthLimit verifies that ManageSieve server enforces line length limits
func TestManageSieve_LineLengthLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	t.Run("command within limit", func(t *testing.T) {
		conn, err := net.Dial("tcp", server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)

		// Read greeting (multi-line capability response)
		for {
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "OK") {
				break
			}
		}

		// Send CAPABILITY command (well within limit)
		fmt.Fprintf(conn, "CAPABILITY\r\n")

		// Read capability response
		foundOK := false
		for {
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "OK") {
				foundOK = true
				break
			}
		}
		if !foundOK {
			t.Error("Expected OK in capability response")
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
		for {
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "OK") {
				break
			}
		}

		// Authenticate first
		auth := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
		fmt.Fprintf(conn, "AUTHENTICATE \"PLAIN\" {%d+}\r\n%s\r\n", len(auth), auth)

		// Read auth response
		for {
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "OK") || strings.HasPrefix(line, "NO") {
				break
			}
		}

		// Send PUTSCRIPT command with a very long script name (but within 8192 bytes)
		// Format: "PUTSCRIPT \"<name>\" {<size>}\r\n"
		// Name can be long, let's try 8000 bytes total line
		longName := strings.Repeat("A", 8000)
		fmt.Fprintf(conn, "PUTSCRIPT \"%s\" {5}\r\n", longName)

		// Should get a response (OK or NO)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}
		line = strings.TrimSpace(line)

		// We expect either OK or NO, but not connection close
		if !strings.HasPrefix(line, "OK") && !strings.HasPrefix(line, "NO") {
			t.Errorf("Expected OK or NO response, got: %s", line)
		}
	})

	t.Run("command exceeds limit", func(t *testing.T) {
		conn, err := net.Dial("tcp", server.Address)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)

		// Read greeting
		for {
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "OK") {
				break
			}
		}

		// Send command exceeding 8192 bytes
		veryLongName := strings.Repeat("X", 10000) // Exceeds limit
		fmt.Fprintf(conn, "PUTSCRIPT \"%s\" {5}\r\n", veryLongName)

		// Should get NO with "line too long" and connection close
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil {
			// Connection might be closed immediately
			t.Logf("Connection closed (expected): %v", err)
			return
		}
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "NO") || !strings.Contains(strings.ToLower(line), "line too long") {
			t.Errorf("Expected 'NO' with 'line too long', got: %s", line)
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
		for {
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "OK") {
				break
			}
		}

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
		if !strings.Contains(line, "NO") {
			t.Errorf("Expected NO response, got: %s", line)
		}
	})
}
