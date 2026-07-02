//go:build integration

package imap_test

import (
	"strings"
	"sync"
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_RenameEmitsOldName verifies RFC 9051 §6.3.6: a successful RENAME sends
// an untagged LIST response carrying the OLDNAME extended data item to an
// IMAP4rev2 client, so the client learns the mailbox's new name.
func TestIMAP_RenameEmitsOldName(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	var mu sync.Mutex
	var listResponses []*imap.ListData

	c, err := imapclient.DialInsecure(server.Address, &imapclient.Options{
		UnilateralDataHandler: &imapclient.UnilateralDataHandler{
			List: func(data *imap.ListData) {
				mu.Lock()
				listResponses = append(listResponses, data)
				mu.Unlock()
			},
		},
	})
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// OLDNAME is an IMAP4rev2 feature — enable it for this session.
	if _, err := c.Enable(imap.CapIMAP4rev2).Wait(); err != nil {
		t.Fatalf("ENABLE IMAP4rev2 failed: %v", err)
	}

	const oldName, newName = "RenameOldName-Src", "RenameOldName-Dst"
	if err := c.Create(oldName, nil).Wait(); err != nil {
		t.Fatalf("CREATE %s failed: %v", oldName, err)
	}
	defer c.Delete(newName).Wait()

	if err := c.Rename(oldName, newName, nil).Wait(); err != nil {
		t.Fatalf("RENAME failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	var found *imap.ListData
	for _, ld := range listResponses {
		if ld.OldName == oldName {
			found = ld
			break
		}
	}
	if found == nil {
		t.Fatalf("RENAME did not emit an untagged LIST with OLDNAME %q; got %d unsolicited LIST responses: %+v", oldName, len(listResponses), listResponses)
	}
	if found.Mailbox != newName {
		t.Errorf("OLDNAME LIST reported mailbox %q, want %q", found.Mailbox, newName)
	}
}

// TestIMAP_RenameInboxEmitsOldName verifies that RENAME INBOX also emits the
// OLDNAME notification (RFC 9051 §6.3.6). Although Sora implements it as a
// create-and-move (a fresh empty INBOX is left behind), the client issued a
// RENAME and must learn where the old INBOX contents now live.
func TestIMAP_RenameInboxEmitsOldName(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	var mu sync.Mutex
	var listResponses []*imap.ListData

	c, err := imapclient.DialInsecure(server.Address, &imapclient.Options{
		UnilateralDataHandler: &imapclient.UnilateralDataHandler{
			List: func(data *imap.ListData) {
				mu.Lock()
				listResponses = append(listResponses, data)
				mu.Unlock()
			},
		},
	})
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if _, err := c.Enable(imap.CapIMAP4rev2).Wait(); err != nil {
		t.Fatalf("ENABLE IMAP4rev2 failed: %v", err)
	}

	const newName = "InboxArchive"
	defer c.Delete(newName).Wait()
	if err := c.Rename("INBOX", newName, nil).Wait(); err != nil {
		t.Fatalf("RENAME INBOX failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	var found *imap.ListData
	for _, ld := range listResponses {
		if ld.Mailbox == newName && ld.OldName != "" {
			found = ld
			break
		}
	}
	if found == nil {
		t.Fatalf("RENAME INBOX did not emit an untagged LIST with OLDNAME; got %d unsolicited LIST responses: %+v", len(listResponses), listResponses)
	}
	if !strings.EqualFold(found.OldName, "INBOX") {
		t.Errorf("OLDNAME reported %q, want INBOX (case-insensitive)", found.OldName)
	}
}
