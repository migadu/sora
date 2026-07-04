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

// dialAndAuthenticate opens a fresh connection to the ManageSieve server and
// authenticates the given account.
func dialAndAuthenticate(t *testing.T, address string, account common.TestAccount) (net.Conn, *bufio.Reader, *bufio.Writer) {
	t.Helper()

	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

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
	return conn, reader, writer
}

// expectClosed asserts the server closed the connection (a rejected
// non-synchronizing {N+} literal commits a body the server can never trust,
// so the stream must not resume).
func expectClosed(t *testing.T, conn net.Conn, reader *bufio.Reader) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	if line, err := reader.ReadString('\n'); err == nil {
		t.Errorf("Expected connection close after rejected non-sync literal, got: %q", line)
	}
}

// TestPutScriptOOMProtection verifies that PUTSCRIPT rejects oversized literals
// before allocating memory, preventing OOM attacks (CVE F-003).
//
// A rejected non-synchronizing {N+} literal also closes the connection: the
// client has committed the body, so the stream cannot safely resume (the body
// would be parsed as commands). The synchronizing {N} form supports
// reject-and-retry on the same connection because no body is committed until
// the server's `+` continuation.
func TestPutScriptOOMProtection(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	// Test 1: A 2GB (int32 max) literal is rejected before any allocation,
	// and the committed {N+} body forces a close.
	t.Run("RejectMaxInt32Literal", func(t *testing.T) {
		conn, reader, writer := dialAndAuthenticate(t, server.Address, account)

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		writer.WriteString("PUTSCRIPT \"test\" {2147483647+}\r\n")
		writer.Flush()

		// Immediate rejection, before any data is sent.
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}
		conn.SetReadDeadline(time.Time{})
		t.Logf("Response: %s", line)

		if !strings.Contains(line, "NO") || !strings.Contains(line, "QUOTA/MAXSIZE") {
			t.Errorf("Expected NO (QUOTA/MAXSIZE) rejection, got: %s", line)
		}
		expectClosed(t, conn, reader)
	})

	// Test 2: A valid literal within limits works.
	t.Run("AcceptValidLiteral", func(t *testing.T) {
		_, reader, writer := dialAndAuthenticate(t, server.Address, account)

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

	// Test 3: A negative literal length is rejected; the malformed {N+}
	// marker committed a body of unknowable size, so the connection closes.
	t.Run("RejectNegativeLiteral", func(t *testing.T) {
		conn, reader, writer := dialAndAuthenticate(t, server.Address, account)

		writer.WriteString("PUTSCRIPT \"bad\" {-1+}\r\n")
		writer.Flush()

		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}
		if !strings.Contains(line, "NO") || !strings.Contains(line, "Invalid literal") {
			t.Errorf("Expected NO (Invalid literal) rejection, got: %s", line)
		}
		expectClosed(t, conn, reader)
	})

	// Test 4: Just over maxScriptSize with the non-sync form: rejected and
	// closed.
	t.Run("RejectJustOverLimit", func(t *testing.T) {
		conn, reader, writer := dialAndAuthenticate(t, server.Address, account)

		oversizeLength := (16 * 1024) + 1
		writer.WriteString(fmt.Sprintf("PUTSCRIPT \"oversize\" {%d+}\r\n", oversizeLength))
		writer.Flush()

		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}
		if !strings.Contains(line, "NO") || !strings.Contains(line, "QUOTA/MAXSIZE") {
			t.Errorf("Expected NO (QUOTA/MAXSIZE) rejection, got: %s", line)
		}
		expectClosed(t, conn, reader)
	})

	// Test 5: The synchronizing {N} form supports reject-and-retry — the
	// connection stays usable after the rejection.
	t.Run("SyncLiteralRejectAndRetry", func(t *testing.T) {
		conn, reader, writer := dialAndAuthenticate(t, server.Address, account)

		oversizeLength := (16 * 1024) + 1
		writer.WriteString(fmt.Sprintf("PUTSCRIPT \"oversize\" {%d}\r\n", oversizeLength))
		writer.Flush()

		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}
		if !strings.Contains(line, "NO") || !strings.Contains(line, "QUOTA/MAXSIZE") {
			t.Errorf("Expected NO (QUOTA/MAXSIZE) rejection, got: %s", line)
		}

		// The server is still responsive on the same connection.
		writer.WriteString("LISTSCRIPTS\r\n")
		writer.Flush()

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		defer conn.SetReadDeadline(time.Time{})

		foundOK := false
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Server not responsive after sync-literal rejection: %v", err)
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

	// Test 6: Proper CRLF handling after a literal (RFC 5804 compliance).
	t.Run("ProperCRLFHandling", func(t *testing.T) {
		conn, reader, writer := dialAndAuthenticate(t, server.Address, account)

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
