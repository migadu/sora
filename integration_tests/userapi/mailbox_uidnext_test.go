//go:build integration

package userapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
)

// listedMailbox is one entry of GET /user/mailboxes.
type listedMailbox struct {
	Name        string `json:"name"`
	Total       int    `json:"total"`
	Unseen      int    `json:"unseen"`
	UIDNext     int64  `json:"uid_next"`
	UIDValidity uint32 `json:"uid_validity"`
}

// TestUserAPI_MailboxListReportsUIDNext: GET /user/mailboxes answered "uid_next": 0 for
// every mailbox (#414), so a client could not use it to notice new mail. uid_next must
// be what IMAP STATUS (UIDNEXT) reports: the UID the next message will get, which RFC
// 9051 §2.3.1.1 says "MUST change whenever new messages are added to the mailbox, even
// if those new messages are subsequently expunged". uid_validity comes with it, since a
// UID is only meaningful together with its UIDVALIDITY.
func TestUserAPI_MailboxListReportsUIDNext(t *testing.T) {
	h := newBodyStateHarness(t)
	ctx := context.Background()

	emptyName := fmt.Sprintf("UIDNext-%d", time.Now().UnixNano())
	resp := h.tc.makeRequest(t, "POST", "/user/mailboxes", map[string]string{"name": emptyName})
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create %s: status %d", emptyName, resp.StatusCode)
	}
	empty, err := h.rdb.GetMailboxByNameWithRetry(ctx, h.accountID, emptyName)
	if err != nil {
		t.Fatal(err)
	}
	// The harness's INBOX comes from GetOrCreateMailboxByName, which reads no UIDVALIDITY.
	inboxRow, err := h.rdb.GetMailboxByNameWithRetry(ctx, h.accountID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}

	insert := func(n int) int64 {
		t.Helper()
		now := time.Now()
		hash := fmt.Sprintf("%016x%047x%d", now.UnixNano(), 0, n)
		_, uid, err := h.rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID: h.accountID, MailboxID: h.inbox.ID, MailboxName: "INBOX",
			S3Domain: "example.com", S3Localpart: "user", ContentHash: hash,
			MessageID: fmt.Sprintf("<uidnext-%d-%d@example.com>", now.UnixNano(), n), Flags: []imap.Flag{},
			InternalDate: now, Size: 64, Subject: "uidnext", SentDate: now,
		}, db.PendingUpload{AccountID: h.accountID, ContentHash: hash, InstanceID: "this-node", Size: 64, CreatedAt: now, UpdatedAt: now})
		if err != nil {
			t.Fatalf("insert message %d: %v", n, err)
		}
		return uid
	}

	list := func() map[string]listedMailbox {
		t.Helper()
		resp := h.tc.makeRequest(t, "GET", "/user/mailboxes", nil)
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("list mailboxes: status %d", resp.StatusCode)
		}
		var out struct {
			Mailboxes []listedMailbox `json:"mailboxes"`
		}
		parseJSON(t, resp, &out)
		byName := make(map[string]listedMailbox, len(out.Mailboxes))
		for _, mb := range out.Mailboxes {
			byName[mb.Name] = mb
		}
		return byName
	}

	insert(1)
	newest := insert(2)
	if _, err := h.rdb.ExpungeMessageUIDsWithRetry(ctx, h.inbox.ID, imap.UID(newest)); err != nil {
		t.Fatal(err)
	}

	got := list()
	inbox, ok := got["INBOX"]
	if !ok {
		t.Fatalf("INBOX missing from listing: %v", got)
	}
	if inbox.UIDNext != newest+1 {
		t.Errorf("INBOX uid_next = %d, want %d (one past the highest UID ever assigned, expunged or not)", inbox.UIDNext, newest+1)
	}
	if inbox.UIDValidity != inboxRow.UIDValidity {
		t.Errorf("INBOX uid_validity = %d, want %d", inbox.UIDValidity, inboxRow.UIDValidity)
	}
	if inbox.Total != 1 {
		t.Errorf("INBOX total = %d, want 1", inbox.Total)
	}
	if mb, ok := got[emptyName]; !ok {
		t.Errorf("%s missing from listing", emptyName)
	} else {
		if mb.UIDNext != 1 {
			t.Errorf("%s uid_next = %d, want 1 for a mailbox that never held a message", emptyName, mb.UIDNext)
		}
		if mb.UIDValidity != empty.UIDValidity {
			t.Errorf("%s uid_validity = %d, want %d", emptyName, mb.UIDValidity, empty.UIDValidity)
		}
	}

	// A new delivery moves uid_next on: this is what a client polls it for.
	latest := insert(3)
	if got := list()["INBOX"].UIDNext; got != latest+1 {
		t.Errorf("after a delivery, INBOX uid_next = %d, want %d", got, latest+1)
	}
}
