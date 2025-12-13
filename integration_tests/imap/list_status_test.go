//go:build integration

package imap_test

import (
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

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
