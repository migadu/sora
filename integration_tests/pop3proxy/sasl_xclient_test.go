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

// TestPOP3ProxySASLWithXCLIENT tests SASL authentication when XCLIENT forwarding is enabled
// This might be where the bug manifests in production
func TestPOP3ProxySASLWithXCLIENT(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server for XCLIENT (no PROXY protocol)
	backendServer, account := common.SetupPOP3ServerForXCLIENT(t)
	defer backendServer.Close()

	// Set up POP3 proxy with XCLIENT enabled
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithXCLIENT(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

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

	// Send AUTH PLAIN without initial response
	_, err = writer.WriteString("AUTH PLAIN\r\n")
	if err != nil {
		t.Fatalf("Failed to send AUTH PLAIN: %v", err)
	}
	writer.Flush()

	// Read continuation
	cont, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read continuation: %v", err)
	}
	t.Logf("Continuation: %s", strings.TrimSpace(cont))

	// Send credentials
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

	// CRITICAL: Try to send STAT immediately after authentication
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	t.Log("Sending STAT command...")
	_, err = writer.WriteString("STAT\r\n")
	if err != nil {
		t.Fatalf("Failed to send STAT (connection closed?): %v", err)
	}
	err = writer.Flush()
	if err != nil {
		t.Fatalf("Failed to flush STAT (connection closed?): %v", err)
	}

	t.Log("Reading STAT response...")
	statResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read STAT response (connection closed after SASL auth?): %v", err)
	}
	t.Logf("STAT response: %s", strings.TrimSpace(statResp))

	if !strings.HasPrefix(statResp, "+OK") {
		t.Fatalf("STAT command failed: %s", statResp)
	}

	t.Log("SUCCESS: SASL authentication with XCLIENT works correctly")
}
