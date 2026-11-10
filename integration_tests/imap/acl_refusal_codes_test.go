//go:build integration

package imap_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// requireResponseCode fails unless err is a tagged NO carrying the given RFC 5530
// response code. A bare NO, or NO [SERVERBUG], is exactly what issue #125 is about:
// a client cannot tell a refusal it can act on from a fault in the server.
func requireResponseCode(t *testing.T, err error, code imap.ResponseCode, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: succeeded, want NO [%s]", what, code)
	}
	var imapErr *imap.Error
	if !errors.As(err, &imapErr) {
		t.Fatalf("%s: got non-IMAP error %v, want NO [%s]", what, err, code)
	}
	if imapErr.Type != imap.StatusResponseTypeNo || imapErr.Code != code {
		t.Fatalf("%s: got %s [%s] %q, want NO [%s]", what, imapErr.Type, imapErr.Code, imapErr.Text, code)
	}
}

// TestACL_SetACLOnPersonalMailboxIsCannot covers the first half of issue #125. Only
// mailboxes in the shared namespace can carry grants, and SETACL on any other mailbox
// can never succeed: RFC 5530 calls that CANNOT ("the operation violates some
// invariant of the server and can never succeed"). It used to answer NO [SERVERBUG].
func TestACL_SetACLOnPersonalMailboxIsCannot(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	grantee, _ := createSecondUser(t, server, "example.com", "personal")

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()
	if err := c.Login(owner.Email, owner.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	personal := fmt.Sprintf("Projects-%d", common.GetTimestamp())
	if err := c.Create(personal, nil).Wait(); err != nil {
		t.Fatalf("Failed to create personal mailbox: %v", err)
	}
	defer func() { c.Delete(personal).Wait() }()

	for _, mailbox := range []string{"INBOX", personal} {
		for mod, arg := range map[imap.RightModification]string{imap.RightModificationReplace: "lr", imap.RightModificationAdd: "+lr"} {
			err := c.SetACL(mailbox, imap.RightsIdentifier(grantee), mod, imap.RightSet("lr")).Wait()
			requireResponseCode(t, err, imap.ResponseCodeCannot, fmt.Sprintf("SETACL %s %s %s", mailbox, grantee, arg))
		}
		err := c.SetACL(mailbox, imap.RightsIdentifier("anyone"), imap.RightModificationReplace, imap.RightSet("lr")).Wait()
		requireResponseCode(t, err, imap.ResponseCodeCannot, fmt.Sprintf("SETACL %s anyone", mailbox))

		// The refusal must not have left a grant behind.
		acl, err := c.GetACL(mailbox).Wait()
		if err != nil {
			t.Fatalf("GETACL %s failed: %v", mailbox, err)
		}
		for _, id := range []imap.RightsIdentifier{imap.RightsIdentifier(grantee), "anyone"} {
			if rights, ok := acl.Rights[id]; ok {
				t.Errorf("GETACL %s lists %s with %q after a refused SETACL", mailbox, id, rights)
			}
		}
	}
}

// TestACL_SetACLCrossDomainIsCannot: a shared mailbox can only be shared within its
// owner's domain. Like a grant on a personal mailbox, a grant to a user in another
// domain can never succeed, and must say so rather than report a server fault.
func TestACL_SetACLCrossDomainIsCannot(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	foreign, _ := createSecondUser(t, server, "other.example.com", "foreign")

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()
	if err := c.Login(owner.Email, owner.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	shared := fmt.Sprintf("Shared/CrossDomain-%d", common.GetTimestamp())
	if err := c.Create(shared, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c.Delete(shared).Wait() }()

	err = c.SetACL(shared, imap.RightsIdentifier(foreign), imap.RightModificationReplace, imap.RightSet("lr")).Wait()
	requireResponseCode(t, err, imap.ResponseCodeCannot, "SETACL to a user in another domain")
}

// TestACL_DeleteACLWithoutEntryIsOK covers the second half of issue #125. RFC 4314
// §3.2: DELETEACL "removes any <identifier,rights> pair for the specified identifier".
// When there is none, the mailbox is already in the state the client asked for, so a
// retried revoke, or two clients revoking at once, must not see a failure. The same
// holds for a SETACL that removes rights from an identifier holding none.
func TestACL_DeleteACLWithoutEntryIsOK(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	grantee, _ := createSecondUser(t, server, "example.com", "revoke")
	never, _ := createSecondUser(t, server, "example.com", "never")

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()
	if err := c.Login(owner.Email, owner.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	shared := fmt.Sprintf("Shared/Revoke-%d", common.GetTimestamp())
	if err := c.Create(shared, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c.Delete(shared).Wait() }()

	if err := c.SetACL(shared, imap.RightsIdentifier(grantee), imap.RightModificationReplace, imap.RightSet("lr")).Wait(); err != nil {
		t.Fatalf("Baseline SETACL failed: %v", err)
	}

	// The first revoke removes the entry; the retry finds nothing and must still be OK.
	for i := 1; i <= 2; i++ {
		if err := c.DeleteACL(shared, imap.RightsIdentifier(grantee)).Wait(); err != nil {
			t.Errorf("DELETEACL %s (attempt %d): %v, want OK", grantee, i, err)
		}
	}

	cases := []struct {
		name    string
		mailbox string
		run     func(mailbox string) error
	}{
		{"DELETEACL user never granted", shared, func(m string) error {
			return c.DeleteACL(m, imap.RightsIdentifier(never)).Wait()
		}},
		{"DELETEACL anyone never granted", shared, func(m string) error {
			return c.DeleteACL(m, imap.RightsIdentifier("anyone")).Wait()
		}},
		{"SETACL -lr on user never granted", shared, func(m string) error {
			return c.SetACL(m, imap.RightsIdentifier(never), imap.RightModificationRemove, imap.RightSet("lr")).Wait()
		}},
		{"SETACL empty rights on user never granted", shared, func(m string) error {
			return c.SetACL(m, imap.RightsIdentifier(never), imap.RightModificationReplace, imap.RightSet("")).Wait()
		}},
		// A personal mailbox carries no grants, so there is never anything to remove.
		{"DELETEACL on INBOX", "INBOX", func(m string) error {
			return c.DeleteACL(m, imap.RightsIdentifier(never)).Wait()
		}},
	}
	for _, tc := range cases {
		if err := tc.run(tc.mailbox); err != nil {
			t.Errorf("%s on %s: %v, want OK", tc.name, tc.mailbox, err)
		}
	}

	acl, err := c.GetACL(shared).Wait()
	if err != nil {
		t.Fatalf("GETACL failed: %v", err)
	}
	for _, id := range []imap.RightsIdentifier{imap.RightsIdentifier(grantee), imap.RightsIdentifier(never), "anyone"} {
		if rights, ok := acl.Rights[id]; ok {
			t.Errorf("GETACL lists %s with %q after revokes", id, rights)
		}
	}
}
