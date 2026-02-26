//go:build integration

package pop3_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestInsecureAuthAutoEnabled tests that when TLS is not configured,
// InsecureAuth is automatically enabled regardless of the setting.
// This is correct behavior: you can't require TLS if TLS isn't configured.
func TestInsecureAuthAutoEnabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create server with InsecureAuth=false BUT TLS=false (default)
	// The server constructor should auto-enable insecureAuth: false || !false = true
	server, account := common.SetupPOP3ServerWithInsecureAuth(t, false)
	defer server.Close()

	client, err := NewPOP3Client(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to POP3 server: %v", err)
	}
	defer client.Close()

	// USER
	if err := client.SendCommand("USER " + account.Email); err != nil {
		t.Fatalf("Failed to send USER: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		t.Fatalf("Expected +OK for USER, got: %s", response)
	}

	// PASS — should succeed because TLS is not configured, so insecureAuth is auto-enabled
	if err := client.SendCommand("PASS " + account.Password); err != nil {
		t.Fatalf("Failed to send PASS: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		t.Fatalf("Expected +OK for PASS (insecureAuth auto-enabled when TLS not configured), got: %s", response)
	}

	t.Log("✓ PASS succeeded: insecureAuth correctly auto-enabled when TLS is not configured")
}

// TestInsecureAuthExplicitlyEnabled tests that InsecureAuth=true works.
func TestInsecureAuthExplicitlyEnabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3ServerWithInsecureAuth(t, true)
	defer server.Close()

	client, err := NewPOP3Client(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to POP3 server: %v", err)
	}
	defer client.Close()

	if err := client.SendCommand("USER " + account.Email); err != nil {
		t.Fatalf("Failed to send USER: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		t.Fatalf("Expected +OK for USER, got: %s", response)
	}

	if err := client.SendCommand("PASS " + account.Password); err != nil {
		t.Fatalf("Failed to send PASS: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		t.Fatalf("Expected +OK for PASS with InsecureAuth=true, got: %s", response)
	}

	t.Log("✓ PASS succeeded with InsecureAuth=true")
}
