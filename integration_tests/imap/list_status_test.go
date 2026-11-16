//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_ListStatusManyMailboxes(t *testing.T) {
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

	// Create 50 mailboxes in a hierarchy
	const numMailboxes = 50
	createdMailboxes := make([]string, 0, numMailboxes)
	for i := 0; i < numMailboxes; i++ {
		name := fmt.Sprintf("ListStatusBatch/Folder%03d", i)
		if err := c.Create(name, nil).Wait(); err != nil {
			t.Fatalf("Failed to create mailbox %s: %v", name, err)
		}
		createdMailboxes = append(createdMailboxes, name)
	}

	// Add messages to some mailboxes (varying counts, some empty, some with unseen)
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("ListStatusBatch/Folder%03d", i)
		// Add i+1 messages to the first 10 mailboxes
		for j := 0; j <= i; j++ {
			msg := fmt.Sprintf("Subject: Test %d-%d\r\n\r\nBody %d-%d", i, j, i, j)
			var flags []imap.Flag
			// Mark even-numbered messages as seen
			if j%2 == 0 {
				flags = []imap.Flag{imap.FlagSeen}
			}
			appendCmd := c.Append(name, int64(len(msg)), &imap.AppendOptions{
				Flags: flags,
				Time:  time.Now(),
			})
			if _, err := appendCmd.Write([]byte(msg)); err != nil {
				t.Fatalf("APPEND write failed: %v", err)
			}
			if err := appendCmd.Close(); err != nil {
				t.Fatalf("APPEND close failed: %v", err)
			}
			if _, err := appendCmd.Wait(); err != nil {
				t.Fatalf("APPEND wait failed: %v", err)
			}
		}
	}

	// Execute LIST with RETURN (STATUS (MESSAGES UNSEEN UIDNEXT))
	options := &imap.ListOptions{
		ReturnStatus: &imap.StatusOptions{
			NumMessages: true,
			NumUnseen:   true,
			UIDNext:     true,
		},
	}

	start := time.Now()
	listCmd := c.List("", "ListStatusBatch/*", options)
	mboxes, err := listCmd.Collect()
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("LIST with STATUS failed: %v", err)
	}

	// Verify all 50 mailboxes returned
	if len(mboxes) != numMailboxes {
		t.Fatalf("Expected %d mailboxes, got %d", numMailboxes, len(mboxes))
	}

	// Verify STATUS data for each mailbox
	for _, mbox := range mboxes {
		if mbox.Status == nil {
			t.Errorf("Mailbox %s missing STATUS data", mbox.Mailbox)
			continue
		}
		if mbox.Status.NumMessages == nil {
			t.Errorf("Mailbox %s missing NumMessages", mbox.Mailbox)
		}
		if mbox.Status.NumUnseen == nil {
			t.Errorf("Mailbox %s missing NumUnseen", mbox.Mailbox)
		}
		if mbox.Status.UIDNext == 0 {
			t.Errorf("Mailbox %s has UIDNext=0", mbox.Mailbox)
		}
	}

	// Verify specific message counts for the first 10 mailboxes
	mboxMap := make(map[string]*imap.ListData, len(mboxes))
	for i := range mboxes {
		mboxMap[mboxes[i].Mailbox] = mboxes[i]
	}

	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("ListStatusBatch/Folder%03d", i)
		mbox, ok := mboxMap[name]
		if !ok {
			t.Errorf("Mailbox %s not found in results", name)
			continue
		}
		expectedMessages := uint32(i + 1)
		if *mbox.Status.NumMessages != expectedMessages {
			t.Errorf("Mailbox %s: expected %d messages, got %d", name, expectedMessages, *mbox.Status.NumMessages)
		}
		// Calculate expected unseen: odd-indexed messages are unseen
		expectedUnseen := uint32((i + 1) / 2) // number of odd indices 0..i
		if *mbox.Status.NumUnseen != expectedUnseen {
			t.Errorf("Mailbox %s: expected %d unseen, got %d", name, expectedUnseen, *mbox.Status.NumUnseen)
		}
	}

	// Verify empty mailboxes
	for i := 10; i < numMailboxes; i++ {
		name := fmt.Sprintf("ListStatusBatch/Folder%03d", i)
		mbox, ok := mboxMap[name]
		if !ok {
			t.Errorf("Mailbox %s not found in results", name)
			continue
		}
		if *mbox.Status.NumMessages != 0 {
			t.Errorf("Mailbox %s: expected 0 messages, got %d", name, *mbox.Status.NumMessages)
		}
		if *mbox.Status.NumUnseen != 0 {
			t.Errorf("Mailbox %s: expected 0 unseen, got %d", name, *mbox.Status.NumUnseen)
		}
	}

	// Verify performance: should complete in reasonable time (<5 seconds for 50 mailboxes)
	if elapsed > 5*time.Second {
		t.Errorf("LIST-STATUS for %d mailboxes took %v (expected <5s)", numMailboxes, elapsed)
	}
	t.Logf("LIST-STATUS for %d mailboxes completed in %v", numMailboxes, elapsed)
}

func TestIMAP_ListStatusEmptyList(t *testing.T) {
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

	// LIST with pattern that matches no mailboxes
	options := &imap.ListOptions{
		ReturnStatus: &imap.StatusOptions{
			NumMessages: true,
			NumUnseen:   true,
			UIDNext:     true,
		},
	}

	listCmd := c.List("", "NonExistentPattern*", options)
	mboxes, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST with STATUS failed: %v", err)
	}

	if len(mboxes) != 0 {
		t.Errorf("Expected 0 mailboxes, got %d", len(mboxes))
	}
}

func TestIMAP_ListStatus(t *testing.T) {
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

	// Make sure INBOX has some state
	testMessage := "Subject: List Status Test\r\n\r\nBody"
	appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen},
		Time:  time.Now(),
	})
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND wait failed: %v", err)
	}

	// Use LIST with RETURN (STATUS (MESSAGES UNSEEN UIDNEXT SIZE))
	options := &imap.ListOptions{
		ReturnStatus: &imap.StatusOptions{
			NumMessages: true,
			NumUnseen:   true,
			UIDNext:     true,
			Size:        true,
		},
	}

	listCmd := c.List("", "INBOX", options)
	mboxes, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST with STATUS failed: %v", err)
	}

	if len(mboxes) != 1 {
		t.Fatalf("Expected 1 mailbox, got %d", len(mboxes))
	}

	inbox := mboxes[0]
	if inbox.Status == nil {
		t.Fatal("LIST response missing STATUS data")
	}

	// Verify status fields are populated
	if inbox.Status.NumMessages == nil {
		t.Error("NumMessages missing in LIST-STATUS response")
	} else if *inbox.Status.NumMessages != 1 {
		t.Errorf("Expected 1 message, got %d", *inbox.Status.NumMessages)
	}

	if inbox.Status.NumUnseen == nil {
		t.Error("NumUnseen missing in LIST-STATUS response")
	} else if *inbox.Status.NumUnseen != 0 {
		t.Errorf("Expected 0 unseen, got %d", *inbox.Status.NumUnseen)
	}

	if inbox.Status.UIDNext == 0 {
		t.Error("UIDNext missing or 0 in LIST-STATUS response")
	}

	if inbox.Status.Size == nil {
		t.Error("Size missing in LIST-STATUS response")
	} else if *inbox.Status.Size != int64(len(testMessage)) {
		t.Errorf("Expected size %d, got %d", len(testMessage), *inbox.Status.Size)
	}

	// Check that unrequested fields are NOT present (e.g. UIDValidity was not requested)
	// Note: go-imap struct might have zero values, but pointers should be nil if possible or just check default
	// UIDValidity is usually a non-zero number.
	if inbox.Status.UIDValidity != 0 {
		// Note: The library might merge status if we previously did a SELECT or STATUS?
		// But in this clean connection/state, it essentially comes from this LIST command.
		// However, some servers might return more than requested? RFC 5819 says "The STATUS response ... MUST include ... specified data items".
		// It doesn't strictly forbid others but usually minimal.
		t.Logf("UIDValidity present: %d (was not requested)", inbox.Status.UIDValidity)
	}
}

// TestIMAP_ListStatusLookupOnlySharedMailboxIsNoSelect verifies RFC 5819 §2 /
// RFC 9051 §6.3.9.2: "If an attempted STATUS for a listed mailbox fails
// because the mailbox can't be selected (e.g., if the "l" ACL right [ACL] is
// granted to the mailbox and the "r" right is not granted ...), the STATUS
// response MUST NOT be returned and the LIST response MUST include the
// \NoSelect attribute." A shared mailbox granted "lr" in the same LIST keeps
// its STATUS response and is not marked \NoSelect.
func TestIMAP_ListStatusLookupOnlySharedMailboxIsNoSelect(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	user := common.CreateTestAccountWithEmail(t, server.ResilientDB,
		fmt.Sprintf("lookup-only-%d@example.com", common.GetTimestamp()), "password2")

	ts := common.GetTimestamp()
	lookupOnly := fmt.Sprintf("Shared/LookupOnly-%d", ts)
	readable := fmt.Sprintf("Shared/Readable-%d", ts)

	oc, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer oc.Logout()
	if err := oc.Login(owner.Email, owner.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}
	for name, rights := range map[string]string{lookupOnly: "l", readable: "lr"} {
		if err := oc.Create(name, nil).Wait(); err != nil {
			t.Fatalf("CREATE %s failed: %v", name, err)
		}
		if err := oc.SetACL(name, imap.RightsIdentifier(user.Email), imap.RightModificationReplace, imap.RightSet(rights)).Wait(); err != nil {
			t.Fatalf("SETACL %s %s failed: %v", name, rights, err)
		}
	}

	uc, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer uc.Logout()
	if err := uc.Login(user.Email, user.Password).Wait(); err != nil {
		t.Fatalf("User login failed: %v", err)
	}
	for _, name := range []string{lookupOnly, readable} {
		if err := uc.Subscribe(name).Wait(); err != nil {
			t.Fatalf("SUBSCRIBE %s failed: %v", name, err)
		}
	}

	hasNoSelect := func(d *imap.ListData) bool {
		for _, a := range d.Attrs {
			if strings.EqualFold(string(a), string(imap.MailboxAttrNoSelect)) {
				return true
			}
		}
		return false
	}

	for _, tc := range []struct {
		name    string
		options *imap.ListOptions
	}{
		{"LIST RETURN (STATUS)", &imap.ListOptions{
			ReturnStatus: &imap.StatusOptions{NumMessages: true},
		}},
		{"LIST (SUBSCRIBED) RETURN (STATUS)", &imap.ListOptions{
			SelectSubscribed: true,
			ReturnStatus:     &imap.StatusOptions{NumMessages: true},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mboxes, err := uc.List("", "Shared/*", tc.options).Collect()
			if err != nil {
				t.Fatalf("LIST failed: %v", err)
			}
			byName := make(map[string]*imap.ListData, len(mboxes))
			for _, m := range mboxes {
				byName[m.Mailbox] = m
			}

			lo, ok := byName[lookupOnly]
			if !ok {
				t.Fatalf("%s not listed, got %d mailboxes", lookupOnly, len(mboxes))
			}
			if lo.Status != nil {
				t.Errorf("%s (rights \"l\"): STATUS MUST NOT be returned, got %+v", lookupOnly, lo.Status)
			}
			if !hasNoSelect(lo) {
				t.Errorf("%s (rights \"l\"): LIST MUST include \\Noselect, got attrs %v", lookupOnly, lo.Attrs)
			}

			rd, ok := byName[readable]
			if !ok {
				t.Fatalf("%s not listed, got %d mailboxes", readable, len(mboxes))
			}
			if rd.Status == nil {
				t.Errorf("%s (rights \"lr\"): want STATUS, got none", readable)
			}
			if hasNoSelect(rd) {
				t.Errorf("%s (rights \"lr\"): must not be \\Noselect, got attrs %v", readable, rd.Attrs)
			}
		})
	}
}
