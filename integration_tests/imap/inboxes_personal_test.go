//go:build integration

package imap_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/integration_tests/common"
)

// The tests of this file are issue #1744. RFC 5465 §6.3: "Inboxes refers to
// all selectable mailboxes in the user's personal namespace(s) to which
// messages may be delivered by a Message Delivery Agent (MDA) ... If the IMAP
// server cannot easily compute this set, it MUST treat "inboxes" as equivalent
// to "personal"." RFC 7377 §2.2 takes ESEARCH's source options from RFC 5465
// §6. Sora does not compute that set (Sieve fileinto can name any personal
// mailbox), so INBOXES is PERSONAL; it covered the INBOX only.

// TestIMAP_ESearchIn_InboxesIsPersonal: the issue's steps. "Lists" stands in for
// a mailbox Sieve fileinto delivers to; the shared mailbox stays out, as it does
// for PERSONAL.
func TestIMAP_ESearchIn_InboxesIsPersonal(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	conn, r := esearchDialLogin(t, server, account.Email, account.Password)
	defer conn.Close()

	lists := fmt.Sprintf("Lists-%d", common.GetTimestamp())
	shared := "Shared/" + lists
	esearchCreate(t, conn, r, "a", lists)
	esearchCreate(t, conn, r, "b", shared)
	esearchAppend(t, conn, r, "c", lists, "probefind")
	esearchAppend(t, conn, r, "d", "INBOX", "probefind")
	esearchAppend(t, conn, r, "e", shared, "probefind")

	got := esearchMailboxes(t, esearchCmdOK(t, conn, r, "f", `ESEARCH IN (INBOXES) RETURN (ALL) SUBJECT "probefind"`))
	esearchAssertHas(t, got, "INBOX", lists)
	if _, ok := got[shared]; ok || len(got) != 2 {
		t.Errorf("ESEARCH IN (INBOXES) answered for %v, want INBOX and %s only", got, lists)
	}
}

// TestIMAP_NotifyInboxesIsPersonal: NOTIFY SET (INBOXES (MessageNew
// MessageExpunge)) reports a new message in a personal mailbox other than the
// INBOX.
func TestIMAP_NotifyInboxesIsPersonal(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rec := newNotifyRecorder()
	watcher := notifyLoginAndSelect(t, server.Address, account, rec.options(), "")
	defer watcher.Logout()

	other := notifyLoginAndSelect(t, server.Address, account, nil, "")
	defer other.Logout()
	lists := fmt.Sprintf("Lists-%d", common.GetTimestamp())
	if err := other.Create(lists, nil).Wait(); err != nil {
		t.Fatalf("Create(%s) = %v", lists, err)
	}

	cmd, err := watcher.Notify(&imap.NotifyOptions{
		Items: []imap.NotifyItem{{
			MailboxSpec: imap.NotifyMailboxSpecInboxes,
			Events:      []imap.NotifyEvent{imap.NotifyEventMessageNew, imap.NotifyEventMessageExpunge},
		}},
	})
	if err != nil {
		t.Fatalf("Notify() = %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Notify().Wait() = %v", err)
	}

	notifyAppend(t, other, lists)
	data := rec.waitStatus(t, lists, 15*time.Second)
	if data.NumMessages == nil || *data.NumMessages != 1 {
		t.Errorf("STATUS %s NumMessages = %v, want 1", lists, data.NumMessages)
	}
}
