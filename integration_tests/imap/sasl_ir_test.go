//go:build integration

package imap_test

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_SASLInitialResponse(t *testing.T) {
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

	// Verify SASL-IR is advertised in CAPABILITY (implied by greeting or explicit command)
	// Let's send CAPABILITY first to be sure
	fmt.Fprintf(conn, "A001 CAPABILITY\r\n")
	foundSaslIr := false
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read capability response: %v", err)
		}
		t.Logf("S: %s", strings.TrimSpace(line))
		if strings.HasPrefix(line, "* CAPABILITY") {
			if strings.Contains(line, "SASL-IR") {
				foundSaslIr = true
			}
		}
		if strings.HasPrefix(line, "A001 OK") {
			break
		}
	}

	if !foundSaslIr {
		t.Log("SASL-IR capability not found in explicit capability response.")
		// It might be in the greeting code [CAPABILITY ...]
	}

	// Prepare PLAIN credentials: \0user\0password
	authZ := "" // authorization identity (empty for same as authC)
	authC := account.Email
	password := account.Password
	msg := []byte(authZ + "\x00" + authC + "\x00" + password)
	encoded := base64.StdEncoding.EncodeToString(msg)

	// Send AUTHENTICATE PLAIN with initial response
	fmt.Fprintf(conn, "A002 AUTHENTICATE PLAIN %s\r\n", encoded)
	// Server should respond with OK immediately, NOT a continuation '+'

	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read auth response: %v", err)
	}
	t.Logf("S: %s", strings.TrimSpace(line))

	if strings.HasPrefix(line, "+") {
		t.Fatal("Server sent continuation request (+), SASL-IR failed")
	}

	if !strings.HasPrefix(line, "A002 OK") {
		t.Fatalf("Authentication failed or SASL-IR rejected. Response: %s", line)
	}

	t.Log("SASL-IR authentication successful")
}
