//go:build integration

package imap_test

import (
	"fmt"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestACL_DelegatedAdminCanSetACL: RFC 4314 §2.1 gives the "a" right to whoever may
// "administer (perform SETACL/DELETEACL/GETACL/LISTRIGHTS)", not only to the owner.
// SETACL by a non-owner holding "a" used to look the mailbox up under the caller's
// own account, find nothing, and answer NO [SERVERBUG].
func TestACL_DelegatedAdminCanSetACL(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	admin, adminPassword := createSecondUser(t, server, "example.com", "admin")
	member, _ := createSecondUser(t, server, "example.com", "member")

	co, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer co.Logout()
	if err := co.Login(owner.Email, owner.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	shared := fmt.Sprintf("Shared/Delegated-%d", common.GetTimestamp())
	if err := co.Create(shared, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { co.Delete(shared).Wait() }()

	if err := co.SetACL(shared, imap.RightsIdentifier(admin), imap.RightModificationReplace, imap.RightSet("lra")).Wait(); err != nil {
		t.Fatalf("Owner SETACL %s lra failed: %v", admin, err)
	}

	ca, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer ca.Logout()
	if err := ca.Login(admin, adminPassword).Wait(); err != nil {
		t.Fatalf("Admin login failed: %v", err)
	}

	// ownerSees returns the member's and anyone's rights as the owner's GETACL lists
	// them, so each step is checked against the owner's mailbox and not the admin's.
	ownerSees := func(step string) (string, string) {
		t.Helper()
		acl, err := co.GetACL(shared).Wait()
		if err != nil {
			t.Fatalf("%s: owner GETACL failed: %v", step, err)
		}
		return acl.Rights[imap.RightsIdentifier(member)].String(), acl.Rights["anyone"].String()
	}

	steps := []struct {
		name       string
		run        func() error
		wantMember string
		wantAnyone string
	}{
		{"SETACL member lr", func() error {
			return ca.SetACL(shared, imap.RightsIdentifier(member), imap.RightModificationReplace, imap.RightSet("lr")).Wait()
		}, "lr", ""},
		{"SETACL member +w", func() error {
			return ca.SetACL(shared, imap.RightsIdentifier(member), imap.RightModificationAdd, imap.RightSet("w")).Wait()
		}, "lrw", ""},
		{"SETACL anyone l", func() error {
			return ca.SetACL(shared, "anyone", imap.RightModificationReplace, imap.RightSet("l")).Wait()
		}, "lrw", "l"},
		{"SETACL member -w", func() error {
			return ca.SetACL(shared, imap.RightsIdentifier(member), imap.RightModificationRemove, imap.RightSet("w")).Wait()
		}, "lr", "l"},
		{"DELETEACL member", func() error {
			return ca.DeleteACL(shared, imap.RightsIdentifier(member)).Wait()
		}, "", "l"},
		{"DELETEACL anyone", func() error {
			return ca.DeleteACL(shared, "anyone").Wait()
		}, "", ""},
	}
	for _, step := range steps {
		if err := step.run(); err != nil {
			t.Fatalf("admin %s: %v, want OK", step.name, err)
		}
		if gotMember, gotAnyone := ownerSees(step.name); gotMember != step.wantMember || gotAnyone != step.wantAnyone {
			t.Fatalf("after admin %s: owner GETACL has member %q anyone %q, want %q and %q",
				step.name, gotMember, gotAnyone, step.wantMember, step.wantAnyone)
		}
	}
}
