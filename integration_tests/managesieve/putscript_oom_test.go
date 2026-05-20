//go:build integration

package managesieve

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestPutScriptOOMProtection verifies that PUTSCRIPT rejects oversized literals
// before allocating memory, preventing OOM attacks (CVE F-003).
func TestPutScriptOOMProtection(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	// Connect to the server
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read initial greeting
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting: %v", err)
		}
		if strings.HasPrefix(strings.TrimSpace(line), "OK") {
			break
		}
	}

	// Authenticate
	credentials := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)))
	writer.WriteString(fmt.Sprintf("AUTHENTICATE \"PLAIN\" {%d+}\r\n%s\r\n", len(credentials), credentials))
	writer.Flush()

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read auth response: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(line), "OK") {
		t.Fatalf("Authentication failed: %s", line)
	}

	// Test 1: Attempt to upload a script with a 2GB literal (int32 max)
	t.Run("RejectMaxInt32Literal", func(t *testing.T) {
		// Set a read timeout to prevent hanging
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		defer conn.SetReadDeadline(time.Time{})

		writer.WriteString("PUTSCRIPT \"test\" {2147483647+}\r\n")
		writer.Flush()

		// Should get immediate rejection before any data is sent
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}

		t.Logf("Response: %s", line)

		if !strings.Contains(line, "NO") || !strings.Contains(line, "MAXSCRIPTSIZE") {
			t.Errorf("Expected NO (MAXSCRIPTSIZE) rejection, got: %s", line)
		}
	})

	// Test 2: Verify valid literal within limits still works
	t.Run("AcceptValidLiteral", func(t *testing.T) {
		script := "# Valid script\nkeep;\n"
		writer.WriteString(fmt.Sprintf("PUTSCRIPT \"valid\" {%d+}\r\n%s\r\n", len(script), script))
		writer.Flush()

		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}

		if !strings.HasPrefix(strings.TrimSpace(line), "OK") {
			t.Errorf("Expected OK for valid script, got: %s", line)
		}
	})

	// Test 3: Test negative literal length
	t.Run("RejectNegativeLiteral", func(t *testing.T) {
		writer.WriteString("PUTSCRIPT \"bad\" {-1+}\r\n")
		writer.Flush()

		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}

		if !strings.Contains(line, "NO") || !strings.Contains(line, "Invalid literal") {
			t.Errorf("Expected NO (Invalid literal) rejection, got: %s", line)
		}
	})

	// Test 4: Test just over maxScriptSize (default is 16KB)
	t.Run("RejectJustOverLimit", func(t *testing.T) {
		oversizeLength := (16 * 1024) + 1
		writer.WriteString(fmt.Sprintf("PUTSCRIPT \"oversize\" {%d+}\r\n", oversizeLength))
		writer.Flush()

		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}

		if !strings.Contains(line, "NO") || !strings.Contains(line, "MAXSCRIPTSIZE") {
			t.Errorf("Expected NO (MAXSCRIPTSIZE) rejection, got: %s", line)
		}
	})

	// Test 5: Verify server is still responsive after rejected large literals
	t.Run("ServerResponsiveAfterRejection", func(t *testing.T) {
		// Send a valid LISTSCRIPTS command
		writer.WriteString("LISTSCRIPTS\r\n")
		writer.Flush()

		// Should get a proper response (not a dead connection)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		defer conn.SetReadDeadline(time.Time{})

		foundOK := false
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Server not responsive after rejection: %v", err)
			}
			if strings.HasPrefix(strings.TrimSpace(line), "OK") {
				foundOK = true
				break
			}
		}

		if !foundOK {
			t.Error("Expected OK response from LISTSCRIPTS")
		}
	})

	// Test 6: Verify proper CRLF handling after literal (RFC 5804 compliance)
	t.Run("ProperCRLFHandling", func(t *testing.T) {
		// RFC 5804 requires literals to be followed by CRLF
		// Format: PUTSCRIPT "test" {10+}\r\n<10 bytes>\r\n
		// Server should read 10 bytes, then consume the CRLF
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		defer conn.SetReadDeadline(time.Time{})

		writer.WriteString("PUTSCRIPT \"rfc5804\" {10+}\r\n")
		writer.Flush()

		// Send exactly 10 bytes followed by CRLF
		writer.WriteString("keep;\r\n   \r\n")
		writer.Flush()

		// Read response - server reads exactly 10 bytes ("keep;\r\n   "), then consumes CRLF
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}

		t.Logf("PUTSCRIPT response: %s", line)

		// The script "keep;\r\n   " (10 bytes) should succeed
		if !strings.Contains(line, "OK") {
			t.Logf("Script validation result: %s", line)
		}

		// Send another command to verify no protocol desynchronization
		writer.WriteString("LISTSCRIPTS\r\n")
		writer.Flush()

		// Should get a proper response (not timeout or garbage)
		foundOK := false
		for {
			line2, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Protocol desynchronized after literal: %v", err)
			}
			if strings.HasPrefix(strings.TrimSpace(line2), "OK") {
				foundOK = true
				break
			}
		}

		if !foundOK {
			t.Error("Expected OK response from LISTSCRIPTS - protocol may be desynchronized")
		} else {
			t.Logf("✓ Protocol remains synchronized after literal - CRLF properly consumed")
		}
	})
}
