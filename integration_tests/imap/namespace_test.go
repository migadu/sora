//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_Namespace(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	namespaces, err := c.Namespace().Wait()
	if err != nil {
		t.Fatalf("NAMESPACE command failed: %v", err)
	}

	// Verify Personal Namespace
	if len(namespaces.Personal) == 0 {
		t.Error("NAMESPACE response missing Personal namespace")
	} else {
		// Expecting standard prefix "" and separator "/" (or dot, depending on server config)
		// Sora uses "/" usually.
		found := false
		for _, ns := range namespaces.Personal {
			t.Logf("Personal Namespace: Prefix='%s', Delimiter='%c'", ns.Prefix, ns.Delim)
			if ns.Prefix == "" {
				found = true
			}
		}
		if !found {
			t.Error("Expected empty prefix in Personal namespace")
		}
	}

	// Verify Other and Shared are present/empty as appropriate
	t.Logf("Other Namespaces: %v", namespaces.Other)
	t.Logf("Shared Namespaces: %v", namespaces.Shared)
}
