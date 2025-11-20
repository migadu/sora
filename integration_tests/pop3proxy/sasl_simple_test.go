//go:build integration

package pop3proxy_test

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

// TestPOP3ProxySASLPlainMinimal is a minimal reproduction test that matches
// the exact sequence from the bug report
func TestPOP3ProxySASLPlainMinimal(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server
	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	// Set up POP3 proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	// Exact sequence from bug report:
	// 1. Connect
	// 2. AUTH PLAIN
	// 3. Send continuation
	// 4. Expect +OK Authentication successful
	// 5. Connection should NOT close - we should be able to send more commands

	conn, err := net.Dial("tcp", proxyAddress)
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
	t.Logf("Greeting: %s", strings.TrimSpace(greeting))

	// Send AUTH PLAIN (without initial response, to match the bug report)
	_, err = writer.WriteString("AUTH PLAIN\r\n")
	if err != nil {
		t.Fatalf("Failed to send AUTH PLAIN: %v", err)
	}
	writer.Flush()

	// Read continuation (should be "+ \r\n")
	cont, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read continuation: %v", err)
	}
	t.Logf("Continuation: %s", strings.TrimSpace(cont))
	if !strings.HasPrefix(cont, "+") {
		t.Fatalf("Expected continuation (+), got: %s", cont)
	}

	// Send credentials: \x00username\x00password
	authString := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
	encoded := base64.StdEncoding.EncodeToString([]byte(authString))
	_, err = writer.WriteString(encoded + "\r\n")
	if err != nil {
		t.Fatalf("Failed to send credentials: %v", err)
	}
	writer.Flush()

	// Read authentication response
	authResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read auth response: %v", err)
	}
	t.Logf("Auth response: %s", strings.TrimSpace(authResp))
	if !strings.HasPrefix(authResp, "+OK") {
		t.Fatalf("Authentication failed: %s", authResp)
	}

	// CRITICAL: Connection should still be open
	// Try to send STAT command immediately
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	t.Log("Sending STAT command...")
	_, err = writer.WriteString("STAT\r\n")
	if err != nil {
		t.Fatalf("Failed to send STAT (connection may have closed): %v", err)
	}
	err = writer.Flush()
	if err != nil {
		t.Fatalf("Failed to flush STAT (connection may have closed): %v", err)
	}

	// Try to read response
	t.Log("Reading STAT response...")
	statResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read STAT response (connection closed after auth?): %v", err)
	}
	t.Logf("STAT response: %s", strings.TrimSpace(statResp))

	if !strings.HasPrefix(statResp, "+OK") {
		t.Fatalf("STAT command failed: %s", statResp)
	}

	t.Log("SUCCESS: Connection remained open after SASL authentication")
}
