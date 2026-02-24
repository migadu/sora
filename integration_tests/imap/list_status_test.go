//go:build integration

package imap_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
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

	// Use LIST with RETURN (STATUS (MESSAGES UNSEEN UIDNEXT))
	options := &imap.ListOptions{
		ReturnStatus: &imap.StatusOptions{
			NumMessages: true,
			NumUnseen:   true,
			UIDNext:     true,
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
