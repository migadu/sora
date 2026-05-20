//go:build integration

package imap_test

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_AppendTooBigLiteralPlus tests that when a client sends an oversized
// literal using LITERAL+ (non-synchronizing), the server properly drains the
// literal data instead of allowing it to leak into the command stream.
//
// Bug reproduction: Apple Mail sends APPEND with {234310148+} (234MB) which exceeds
// the 25MB limit. The server responds with NO [TOOBIG], but the client has already
// started sending the literal data. If the server doesn't drain this data, it bleeds
// into the command parser, causing "expected SP" errors and treating message headers
// as IMAP commands (e.g., "Subject: BAD Unknown command").
func TestIMAP_AppendTooBigLiteralPlus(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Use raw TCP connection to have full control over the protocol
	addr := server.Address
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("Server greeting: %s", strings.TrimSpace(greeting))

	// Helper to send command and read response
	send := func(cmd string) {
		t.Logf("C: %s", cmd)
		writer.WriteString(cmd + "\r\n")
		writer.Flush()
	}

	readLine := func() string {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read line: %v", err)
		}
		t.Logf("S: %s", strings.TrimSpace(line))
		return line
	}

	expectOK := func(tag string) {
		for {
			line := readLine()
			if strings.HasPrefix(line, tag+" OK") {
				return
			}
			if strings.HasPrefix(line, tag+" NO") || strings.HasPrefix(line, tag+" BAD") {
				t.Fatalf("Expected OK, got: %s", line)
			}
		}
	}

	// Login
	send(fmt.Sprintf("A001 LOGIN %s %s", account.Email, account.Password))
	expectOK("A001")

	// Select INBOX
	send("A002 SELECT INBOX")
	expectOK("A002")

	// Create a message that would be too large
	// APPENDLIMIT is 25MB (26214400 bytes) by default
	oversizedBytes := 26214400 + 1000 // Slightly over the limit

	// Construct a realistic message with Apple Mail headers (similar to production)
	messageHeader := strings.ReplaceAll(`Subject: =?utf-8?Q?Re=3A_Test_Message?=
Mime-Version: 1.0 (Mac OS X Mail 16.0)
Content-Type: multipart/alternative;
	boundary="Apple-Mail-Test"
From: test@example.com
To: recipient@example.com
Date: Sun, 16 Mar 2026 10:00:00 -0800
Message-Id: <test@example.com>

--Apple-Mail-Test
Content-Type: text/plain; charset=utf-8

`, "\n", "\r\n")

	// Calculate how much padding we need to reach the oversized limit
	paddingSize := oversizedBytes - len(messageHeader)
	if paddingSize < 0 {
		paddingSize = 0
	}

	// Send APPEND with LITERAL+ (non-synchronizing) - note the + after the size
	// This tells the server we're sending the literal immediately without waiting for continuation
	send(fmt.Sprintf("A003 APPEND INBOX (\\Seen) {%d+}", oversizedBytes))

	// Immediately send the literal data (this is what LITERAL+ allows)
	// In a real scenario with a 234MB message, the client would send all of it
	// For testing, we send the header first
	writer.WriteString(messageHeader)

	// Send some padding to reach the oversized limit
	// We'll send it in chunks to avoid memory issues
	chunkSize := 1024 * 1024 // 1MB chunks
	chunk := bytes.Repeat([]byte("X"), chunkSize)
	remaining := paddingSize
	for remaining > 0 {
		if remaining < chunkSize {
			writer.Write(chunk[:remaining])
			remaining = 0
		} else {
			writer.Write(chunk)
			remaining -= chunkSize
		}
	}
	writer.WriteString("\r\n") // End of literal
	writer.Flush()

	// Read the server's response - should be NO [TOOBIG]
	foundTooBig := false
	for {
		line := readLine()

		// Check for TOOBIG response
		if strings.Contains(line, "[TOOBIG]") {
			foundTooBig = true
			t.Logf("Got expected TOOBIG response: %s", strings.TrimSpace(line))
		}

		// The bug manifests as command parsing errors
		if strings.Contains(line, "expected SP") {
			t.Errorf("BUG DETECTED: Command parser error after TOOBIG: %s", line)
		}
		if strings.Contains(line, "Subject:") && strings.Contains(line, "BAD") {
			t.Errorf("BUG DETECTED: Message header leaked into command stream: %s", line)
		}

		// Look for the tagged response
		if strings.HasPrefix(line, "A003 ") {
			if !strings.HasPrefix(line, "A003 NO") {
				t.Errorf("Expected A003 NO [TOOBIG], got: %s", line)
			}
			break
		}
	}

	if !foundTooBig {
		t.Error("Did not receive [TOOBIG] response code")
	}

	// Most importantly: verify the connection is still usable
	// Send a valid command to ensure the stream isn't corrupted
	send("A004 NOOP")
	expectOK("A004")

	// Try another command to be extra sure
	send("A005 SELECT INBOX")
	expectOK("A005")

	// Logout
	send("A006 LOGOUT")
	expectOK("A006")

	t.Log("Connection remained stable after TOOBIG literal - test passed!")
}

// TestIMAP_AppendTooBigSynchronizing tests the same scenario but with
// synchronizing literals (without the +). Per RFC 3501, the server MUST
// send continuation for synchronizing literals before the client sends data.
// The server can only reject AFTER reading the literal (in the handler).
func TestIMAP_AppendTooBigSynchronizing(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	addr := server.Address
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("Server greeting: %s", strings.TrimSpace(greeting))

	send := func(cmd string) {
		t.Logf("C: %s", cmd)
		writer.WriteString(cmd + "\r\n")
		writer.Flush()
	}

	readLine := func() string {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read line: %v", err)
		}
		t.Logf("S: %s", strings.TrimSpace(line))
		return line
	}

	expectOK := func(tag string) {
		for {
			line := readLine()
			if strings.HasPrefix(line, tag+" OK") {
				return
			}
			if strings.HasPrefix(line, tag+" NO") || strings.HasPrefix(line, tag+" BAD") {
				t.Fatalf("Expected OK, got: %s", line)
			}
		}
	}

	// Login
	send(fmt.Sprintf("A001 LOGIN %s %s", account.Email, account.Password))
	expectOK("A001")

	// Send APPEND with synchronizing literal (no +)
	oversizedBytes := 26214400 + 1000 // Over 25MB default limit
	send(fmt.Sprintf("A002 APPEND INBOX {%d}", oversizedBytes))

	// With Migadu's go-imap fork, the server checks the literal size from {size}
	// BEFORE sending continuation response. This is an optimization that prevents
	// memory exhaustion by rejecting oversized messages immediately without reading data.
	// The server responds with NO [TOOBIG] directly, without sending "+ " continuation.
	line := readLine()
	if !strings.HasPrefix(line, "A002 NO") {
		t.Fatalf("Expected NO [TOOBIG] response, got: %s", line)
	}
	if !strings.Contains(line, "[TOOBIG]") {
		t.Fatalf("Expected [TOOBIG] response code, got: %s", line)
	}
	t.Logf("Got expected TOOBIG response: %s", strings.TrimSpace(line))

	// Connection should be fine
	send("A003 NOOP")
	expectOK("A003")

	// Logout
	send("A004 LOGOUT")
	expectOK("A004")

	t.Log("Synchronizing literal correctly rejected - test passed!")
}
