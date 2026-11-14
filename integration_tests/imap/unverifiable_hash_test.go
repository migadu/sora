//go:build integration

package imap_test

import (
	"context"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAPLoginWithUnverifiableStoredHash: a stored password value VerifyPassword
// cannot check (here the password itself, pasted into the hash field before #499
// refused it) fails the login with its own reason, unverifiable_hash, in the line
// that names the address. It used to be logged as invalid_password, and the ERROR
// that VerifyPassword logs carries no address.
func TestIMAPLoginWithUnverifiableStoredHash(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	if err := server.ResilientDB.UpdatePasswordWithRetry(context.Background(), account.Email, account.Password); err != nil {
		t.Fatalf("store the password in the hash field: %v", err)
	}
	logs := common.CaptureLogs(t)

	if reply := imapLoginReply(t, server.Address, account.Email, account.Password); !strings.HasPrefix(reply, "a1 NO") {
		t.Fatalf("LOGIN against an unverifiable stored hash: %q, want a1 NO", reply)
	}
	logs.WaitForLine(t, "authentication failed", account.Email, "reason=unverifiable_hash")
}
