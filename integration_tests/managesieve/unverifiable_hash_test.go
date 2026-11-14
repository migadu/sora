//go:build integration

package managesieve

import (
	"context"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestManageSieveLoginWithUnverifiableStoredHash: a stored password value
// VerifyPassword cannot check (here the password itself, pasted into the hash field
// before #499 refused it) fails the login with its own reason, unverifiable_hash, in
// the line that names the address. It used to be logged as invalid_password, and the
// ERROR that VerifyPassword logs carries no address.
func TestManageSieveLoginWithUnverifiableStoredHash(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupManageSieveServer(t)
	defer server.Close()
	if err := server.ResilientDB.UpdatePasswordWithRetry(context.Background(), account.Email, account.Password); err != nil {
		t.Fatalf("store the password in the hash field: %v", err)
	}
	logs := common.CaptureLogs(t)

	if reply := msLogin(t, server.Address, account.Email, account.Password); !strings.HasPrefix(reply, "NO") {
		t.Fatalf("LOGIN against an unverifiable stored hash: %q, want NO", reply)
	}
	logs.WaitForLine(t, "authentication failed", account.Email, "reason=unverifiable_hash")
}
