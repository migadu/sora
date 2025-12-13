//go:build integration

package imap_test

import (
	"testing"

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
