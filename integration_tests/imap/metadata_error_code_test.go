//go:build integration

package imap_test

import (
	"errors"
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_Metadata_NonexistentMailbox_CleanError is a regression test for audit
// finding H7 (2026-07-01 IMAP command-correctness audit).
//
// server/imap/cmd_metadata.go returns plain fmt.Errorf(...) for a non-existent
// mailbox (and for permission denials). go-imap only surfaces *imap.Error
// verbatim; any other error becomes `NO [SERVERBUG] Internal server error` and is
// logged as a handler fault. A GETMETADATA/SETMETADATA on a missing mailbox is
// normal client behavior, not a server bug.
//
// Expected: a clean tagged NO (e.g. [NONEXISTENT]); never [SERVERBUG].
// Actual   (bug): `NO [SERVERBUG] Internal server error`.
//
// Fix: wrap these returns in *imap.Error with an appropriate response code.
func TestIMAP_Metadata_NonexistentMailbox_CleanError(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	assertCleanNo := func(op string, err error) {
		if err == nil {
			t.Errorf("%s on a nonexistent mailbox should fail, got success", op)
			return
		}
		var imapErr *imap.Error
		if !errors.As(err, &imapErr) {
			t.Errorf("%s: expected *imap.Error, got %T: %v", op, err, err)
			return
		}
		t.Logf("%s -> %s [%s] %s", op, imapErr.Type, imapErr.Code, imapErr.Text)
		if imapErr.Code == imap.ResponseCodeServerBug {
			t.Errorf("REGRESSION: %s on a nonexistent mailbox returned NO [SERVERBUG] %q; "+
				"a missing mailbox must yield a clean NO (e.g. [NONEXISTENT]), not an internal server error.",
				op, imapErr.Text)
		}
	}

	_, getErr := c.GetMetadata("NonExistentMailbox", []string{"/private/comment"}, nil).Wait()
	assertCleanNo("GETMETADATA", getErr)

	value := []byte("value")
	setErr := c.SetMetadata("NonExistentMailbox", map[string]*[]byte{"/private/comment": &value}).Wait()
	assertCleanNo("SETMETADATA", setErr)
}
