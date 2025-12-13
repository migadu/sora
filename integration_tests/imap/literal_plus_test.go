//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_LiteralPlus(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect via raw TCP
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("S: %s", strings.TrimSpace(line))

	// Login
	fmt.Fprintf(conn, "A001 LOGIN %s %s\r\n", account.Email, account.Password)
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read login response: %v", err)
	}
	if !strings.HasPrefix(line, "A001 OK") {
		t.Fatalf("Login failed: %s", line)
	}

	// Verify LITERAL+ is advertised in CAPABILITY
	fmt.Fprintf(conn, "A002 CAPABILITY\r\n")
	foundLiteralPlus := false
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read capability response: %v", err)
		}
		t.Logf("S: %s", strings.TrimSpace(line))
		if strings.HasPrefix(line, "* CAPABILITY") {
			if strings.Contains(line, "LITERAL+") {
				foundLiteralPlus = true
			}
		}
		if strings.HasPrefix(line, "A002 OK") {
			break
		}
	}

	if !foundLiteralPlus {
		t.Skip("LITERAL+ capability not advertised, skipping test")
	}

	// Select INBOX
	fmt.Fprintf(conn, "A003 SELECT INBOX\r\n")
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read select response: %v", err)
		}
		if strings.HasPrefix(line, "A003 ") {
			if !strings.HasPrefix(line, "A003 OK") {
				t.Fatalf("Select failed: %s", line)
			}
			break
		}
	}

	// Test APPEND with LITERAL+
	// Format: {size+}
	messageData := "From: literalplus@example.com\r\nSubject: Literal Plus Test\r\n\r\nBody"
	msgLen := len(messageData)

	// Send command with +
	// IMPORTANT: We send the data IMMEDIATELY after the CRLF, without waiting for a reponse.
	// If the server didn't support LITERAL+, verification would be hard here because we are blasting data.
	// But failure mode would be the server treating data as separate commands or erroring.
	// Correct behavior: Server processes it and returns OK.

	// Prepare full payload
	command := fmt.Sprintf("A004 APPEND INBOX {%d+}\r\n%s\r\n", msgLen, messageData)

	// Write everything in one go or quickly
	fmt.Fprint(conn, command)

	// Set a read deadline to ensure we don't hang if server is waiting for us (which would mean it sent a + and is waiting, but we already sent data, so it might be ignoring it or buffering)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read response
	// We expect NO continuation line ("+ ...")
	// We expect "A004 OK ..." eventually.

	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read append response: %v", err)
		}
		t.Logf("S: %s", strings.TrimSpace(line))

		if strings.HasPrefix(line, "+") {
			t.Error("Server sent continuation request (+), LITERAL+ failed (server treated it as normal literal or ignored +)")
		}

		if strings.HasPrefix(line, "A004 ") {
			if !strings.HasPrefix(line, "A004 OK") {
				t.Fatalf("APPEND failed: %s", line)
			}
			break
		}
	}

	t.Log("LITERAL+ APPEND successful")
}
