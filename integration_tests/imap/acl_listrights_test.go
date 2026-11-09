//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// TestACL_ListRightsMatchesWhatCanBeGranted: RFC 4314 §2 makes LISTRIGHTS the way
// "a client can discover the set of rights that may be granted to a given identifier
// in the ACL for a given mailbox name", and lets an implementation "force rights to
// always or never be granted to particular identifiers". LISTRIGHTS used to offer
// every right to everyone everywhere, while SETACL refuses any grant on a mailbox
// outside the shared namespace (NO [CANNOT]) and the owner always holds every right.
func TestACL_ListRightsMatchesWhatCanBeGranted(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	other, _ := createSecondUser(t, server, "example.com", "listrights")

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
	shared := fmt.Sprintf("Shared/ListRights-%d", common.GetTimestamp())
	if err := c.Create(shared, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c.Delete(shared).Wait() }()

	listRights := func(mailbox string, id imap.RightsIdentifier) *imapclient.ListRightsData {
		t.Helper()
		data, err := c.ListRights(mailbox, id).Wait()
		if err != nil {
			t.Fatalf("LISTRIGHTS %s %s: %v", mailbox, id, err)
		}
		return data
	}
	optional := func(data *imapclient.ListRightsData) string {
		var sb strings.Builder
		for _, grp := range data.OptionalRights {
			sb.WriteString(grp.String())
		}
		return sb.String()
	}

	// Nothing can be granted on a personal mailbox.
	for _, mailbox := range []string{"INBOX", personal} {
		for _, id := range []imap.RightsIdentifier{imap.RightsIdentifier(other), "anyone"} {
			data := listRights(mailbox, id)
			if req, opt := data.RequiredRights.String(), optional(data); req != "" || opt != "" {
				t.Errorf("LISTRIGHTS %s %s = required %q optional %q, want nothing grantable", mailbox, id, req, opt)
			}
		}
	}

	// The owner always holds every right, so all are required and nothing is
	// optional: not even the virtual c/d (RFC 4314 §2.1.1), which go-imap now puts
	// with the required rights when all their members are required (go-imap #112).
	for _, mailbox := range []string{"INBOX", personal, shared} {
		data := listRights(mailbox, imap.RightsIdentifier(owner.Email))
		if !hasAllRights(data.RequiredRights, imap.RightSet(db.AllACLRights+"cd")) {
			t.Errorf("LISTRIGHTS %s <owner>: required %q, want all of %q", mailbox, data.RequiredRights, db.AllACLRights+"cd")
		}
		if opt := optional(data); opt != "" {
			t.Errorf("LISTRIGHTS %s <owner>: optional %q, want none: the owner always holds every right", mailbox, opt)
		}
	}

	// On a shared mailbox everyone else can still be granted each right on its own.
	for _, id := range []imap.RightsIdentifier{imap.RightsIdentifier(other), "anyone"} {
		data := listRights(shared, id)
		if req, opt := data.RequiredRights.String(), optional(data); req != "" || !hasAllRights(imap.RightSet(opt), imap.RightSet(db.AllACLRights)) {
			t.Errorf("LISTRIGHTS %s %s = required %q optional %q, want every right optional", shared, id, req, opt)
		}
	}
}
