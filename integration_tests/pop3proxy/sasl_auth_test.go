//go:build integration

package pop3proxy_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestPOP3ProxyAuthenticationMethods tests both USER/PASS and SASL PLAIN authentication
// and verifies the connection remains open after authentication to allow subsequent commands
func TestPOP3ProxyAuthenticationMethods(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend POP3 server
	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	// Set up POP3 proxy
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	t.Run("USER_PASS_Authentication", func(t *testing.T) {
		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		// Send USER command
		err = client.SendCommand("USER " + account.Email)
		if err != nil {
			t.Fatalf("Failed to send USER command: %v", err)
		}

		resp, err := client.ReadResponse()
		if err != nil {
			t.Fatalf("Failed to read USER response: %v", err)
		}

		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("USER command failed: %s", resp)
		}

		// Send PASS command
		err = client.SendCommand("PASS " + account.Password)
		if err != nil {
			t.Fatalf("Failed to send PASS command: %v", err)
		}

		resp, err = client.ReadResponse()
		if err != nil {
			t.Fatalf("Failed to read PASS response: %v", err)
		}

		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("PASS command failed: %s", resp)
		}

		t.Logf("USER/PASS authentication successful: %s", resp)

		// Verify connection is still open by sending STAT command
		err = client.SendCommand("STAT")
		if err != nil {
			t.Fatalf("Failed to send STAT command after authentication: %v", err)
		}

		resp, err = client.ReadResponse()
		if err != nil {
			t.Fatalf("Failed to read STAT response: %v (connection may have closed)", err)
		}

		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("STAT command failed: %s", resp)
		}

		t.Logf("STAT response after USER/PASS: %s", resp)
	})

	t.Run("SASL_PLAIN_WithInitialResponse", func(t *testing.T) {
		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		// Build SASL PLAIN initial response: \x00username\x00password
		authString := "\x00" + account.Email + "\x00" + account.Password
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		// Send AUTH PLAIN with initial response
		err = client.SendCommand("AUTH PLAIN " + encoded)
		if err != nil {
			t.Fatalf("Failed to send AUTH PLAIN command: %v", err)
		}

		// Read authentication response
		resp, err := client.ReadResponse()
		if err != nil {
			t.Fatalf("Failed to read AUTH response: %v", err)
		}

		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("AUTH PLAIN failed: %s", resp)
		}

		t.Logf("Authentication successful: %s", resp)

		// CRITICAL: Try to send STAT command to verify connection is still open
		err = client.SendCommand("STAT")
		if err != nil {
			t.Fatalf("Failed to send STAT command after authentication: %v", err)
		}

		resp, err = client.ReadResponse()
		if err != nil {
			t.Fatalf("Failed to read STAT response: %v (connection may have closed)", err)
		}

		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("STAT command failed: %s", resp)
		}

		t.Logf("STAT response: %s", resp)
	})

	t.Run("SASL_PLAIN_WithContinuation", func(t *testing.T) {
		client, err := NewPOP3Client(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 proxy: %v", err)
		}
		defer client.Close()

		// Send AUTH PLAIN without initial response
		err = client.SendCommand("AUTH PLAIN")
		if err != nil {
			t.Fatalf("Failed to send AUTH PLAIN command: %v", err)
		}

		// Read continuation request (should be "+ \r\n")
		resp, err := client.ReadResponse()
		if err != nil {
			t.Fatalf("Failed to read continuation: %v", err)
		}

		if !strings.HasPrefix(resp, "+") {
			t.Fatalf("Expected continuation (+), got: %s", resp)
		}

		// Build SASL PLAIN response: \x00username\x00password
		authString := "\x00" + account.Email + "\x00" + account.Password
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		// Send credentials
		err = client.SendCommand(encoded)
		if err != nil {
			t.Fatalf("Failed to send credentials: %v", err)
		}

		// Read authentication response
		resp, err = client.ReadResponse()
		if err != nil {
			t.Fatalf("Failed to read AUTH response: %v", err)
		}

		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("AUTH PLAIN failed: %s", resp)
		}

		t.Logf("Authentication successful: %s", resp)

		// CRITICAL: Try to send STAT command to verify connection is still open
		err = client.SendCommand("STAT")
		if err != nil {
			t.Fatalf("Failed to send STAT command after authentication: %v", err)
		}

		resp, err = client.ReadResponse()
		if err != nil {
			t.Fatalf("Failed to read STAT response: %v (connection may have closed)", err)
		}

		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("STAT command failed: %s", resp)
		}

		t.Logf("STAT response: %s", resp)
	})
}
