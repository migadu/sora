//go:build integration

package managesieve

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/managesieve"
)

func TestManageSieveExtensionValidation(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create test database and account with custom extensions configuration
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	// Create ManageSieve server with envelope extension enabled (but not variables)
	server, err := managesieve.New(
		context.Background(),
		"test",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			InsecureAuth:        true, // Enable PLAIN auth for testing
			SupportedExtensions: []string{"fileinto", "vacation", "envelope"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		server.Start(errChan)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	defer func() {
		server.Close()
		select {
		case <-errChan:
		default:
		}
	}()

	// Connect and authenticate
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Authenticate (this handles reading the greeting too)
	authenticateManageSieve(t, reader, writer, account)

	// Test 1: Script with supported envelope extension should succeed
	t.Log("=== Testing script with supported envelope extension ===")
	envelopeScript := `require ["fileinto", "envelope"]; if envelope :is "from" "example.com" { fileinto "Domain"; } else { fileinto "INBOX"; }`

	// Use non-synchronizing literal: PUTSCRIPT "name" {length+} scriptcontent
	// With {length+}, server does NOT send continuation response (RFC 5804 §4)
	literalCommand := fmt.Sprintf("PUTSCRIPT \"envelope_test\" {%d+}\r\n%s", len(envelopeScript), envelopeScript)
	writer.WriteString(literalCommand + "\r\n")
	writer.Flush()

	// Read the final response (no continuation response for non-synchronizing literals)
	response := readResponse(t, reader)
	if !strings.Contains(response, "OK") {
		t.Errorf("Script with supported envelope extension should succeed: %s", response)
	} else {
		t.Logf("Envelope extension script accepted: %s", strings.TrimSpace(response))
	}

	// Test 2: Script with unsupported variables extension should fail
	t.Log("=== Testing script with unsupported variables extension ===")
	variablesScript := `require ["fileinto", "variables"]; set "domain" "example.com"; if header :contains "from" "${domain}" { fileinto "Domain"; }`

	// Use non-synchronizing literal: PUTSCRIPT "name" {length+} scriptcontent
	literalCommand2 := fmt.Sprintf("PUTSCRIPT \"variables_test\" {%d+}\r\n%s", len(variablesScript), variablesScript)
	writer.WriteString(literalCommand2 + "\r\n")
	writer.Flush()

	// Read the final response (no continuation response for non-synchronizing literals)
	response = readResponse(t, reader)
	if strings.Contains(response, "OK") {
		t.Errorf("Script with unsupported variables extension should fail: %s", response)
	} else {
		t.Logf("Variables extension script correctly rejected: %s", strings.TrimSpace(response))
	}

	// Send LOGOUT to cleanly close the session
	writer.WriteString("LOGOUT\r\n")
	writer.Flush()

	// Read the BYE response
	_ = readResponse(t, reader)
}
