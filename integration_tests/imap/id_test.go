//go:build integration

package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_ID(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	// 1. Send ID command before login (Pre-auth)
	// Server should accept it.
	clientInfo := imap.IDData{
		Name:    "SoraIntegrationTest",
		Version: "1.0",
	}
	serverID, err := c.ID(&clientInfo).Wait()
	if err != nil {
		t.Fatalf("ID command failed pre-auth: %v", err)
	}
	t.Logf("Server ID (pre-auth): %v", serverID)

	// 2. Login
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// 3. Send ID command after login (Post-auth)
	// Some servers only accept it once, but RFC 2971 says it can be sent multiple times.
	// "A client MAY send the ID command at any time..."
	serverID, err = c.ID(&clientInfo).Wait()
	if err != nil {
		t.Logf("ID command failed post-auth (might be allowed): %v", err)
	} else {
		t.Logf("Server ID (post-auth): %v", serverID)

		// Verify server returned something (usually name/version)
		if serverID.Name == "" {
			t.Log("Server ID Name is empty")
		}
	}
}

// TestIMAP_ID_BareCommand verifies the server is resilient to a bare "ID"
// command sent with no argument at all (e.g. Open-Xchange sends "ID" instead of
// the RFC 2971 compliant "ID NIL"). The server must treat it as NIL and reply
// with its own ID + OK, never "NO [SERVERBUG] Internal server error".
//
// The imapclient library always formats ID correctly, so this drives the
// protocol over a raw socket to reproduce the malformed input.
func TestIMAP_ID_BareCommand(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := common.SetupIMAPServer(t)
	defer server.Close()

	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	br := bufio.NewReader(conn)

	// Read the server greeting.
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}

	// Send a bare ID command with no argument (the Open-Xchange behaviour).
	if _, err := conn.Write([]byte("a1 ID\r\n")); err != nil {
		t.Fatalf("Failed to write ID command: %v", err)
	}

	// Collect lines until the tagged "a1 " response.
	var taggedLine string
	var sawUntaggedID bool
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response (got so far: %q): %v", taggedLine, err)
		}
		line = strings.TrimRight(line, "\r\n")
		t.Logf("S: %s", line)
		if strings.HasPrefix(line, "* ID") {
			sawUntaggedID = true
		}
		if strings.HasPrefix(line, "a1 ") {
			taggedLine = line
			break
		}
	}

	if !strings.HasPrefix(taggedLine, "a1 OK") {
		t.Fatalf("Bare ID command was not accepted: got %q, want \"a1 OK ...\"", taggedLine)
	}
	if strings.Contains(taggedLine, "SERVERBUG") {
		t.Fatalf("Bare ID command produced a SERVERBUG: %q", taggedLine)
	}
	if !sawUntaggedID {
		t.Errorf("Expected an untagged \"* ID (...)\" response, none received")
	}
}
