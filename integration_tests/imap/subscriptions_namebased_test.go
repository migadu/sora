//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// listSubscribed returns the LIST (SUBSCRIBED) entries matching pattern.
func listSubscribed(t *testing.T, c *imapclient.Client, pattern string) []*imap.ListData {
	t.Helper()
	mboxes, err := c.List("", pattern, &imap.ListOptions{SelectSubscribed: true}).Collect()
	if err != nil {
		t.Fatalf("LIST (SUBSCRIBED) %q failed: %v", pattern, err)
	}
	return mboxes
}

func findSub(mboxes []*imap.ListData, name string) *imap.ListData {
	for _, m := range mboxes {
		if m.Mailbox == name {
			return m
		}
	}
	return nil
}

// TestIMAP_SubscribeNonexistentPersists verifies RFC 3501 §6.3.6 / RFC 9051
// §6.3.7: SUBSCRIBE to a name with no mailbox persists the subscription, and
// LIST (SUBSCRIBED) reports it flagged \NonExistent. Previously the subscription
// was a bool on the mailbox row, so subscribing a nonexistent name returned OK
// but persisted nothing and could never be listed.
func TestIMAP_SubscribeNonexistentPersists(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	const ghost = "GhostBox"
	if err := c.Subscribe(ghost).Wait(); err != nil {
		t.Fatalf("SUBSCRIBE to nonexistent mailbox failed: %v", err)
	}

	got := findSub(listSubscribed(t, c, ghost), ghost)
	if got == nil {
		t.Fatalf("subscribed nonexistent mailbox %q not reported by LIST (SUBSCRIBED)", ghost)
	}
	if !hasAttr(got.Attrs, imap.MailboxAttrNonExistent) {
		t.Errorf("subscribed nonexistent mailbox %q should carry \\NonExistent; attrs=%v", ghost, got.Attrs)
	}

	// UNSUBSCRIBE removes it again.
	if err := c.Unsubscribe(ghost).Wait(); err != nil {
		t.Fatalf("UNSUBSCRIBE failed: %v", err)
	}
	if got := findSub(listSubscribed(t, c, ghost), ghost); got != nil {
		t.Errorf("%q still subscribed after UNSUBSCRIBE: %v", ghost, got)
	}
}

// TestIMAP_SubscriptionSurvivesDelete verifies that a subscription survives the
// deletion of its mailbox and is then reported \NonExistent (RFC 9051 §6.3.7 — a
// server MUST NOT remove a name from the subscription list when its mailbox is
// deleted).
func TestIMAP_SubscriptionSurvivesDelete(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	const name = "SurviveMe"
	if err := c.Create(name, nil).Wait(); err != nil {
		t.Fatalf("CREATE failed: %v", err)
	}
	if err := c.Subscribe(name).Wait(); err != nil {
		t.Fatalf("SUBSCRIBE failed: %v", err)
	}

	// While live, it must be subscribed (and NOT \NonExistent).
	if got := findSub(listSubscribed(t, c, name), name); got == nil {
		t.Fatalf("live subscribed mailbox %q not in LIST (SUBSCRIBED)", name)
	} else if hasAttr(got.Attrs, imap.MailboxAttrNonExistent) {
		t.Errorf("live mailbox %q wrongly flagged \\NonExistent", name)
	}

	if err := c.Delete(name).Wait(); err != nil {
		t.Fatalf("DELETE failed: %v", err)
	}

	// After deletion, the subscription survives and is flagged \NonExistent.
	got := findSub(listSubscribed(t, c, name), name)
	if got == nil {
		t.Fatalf("subscription for %q did not survive DELETE", name)
	}
	if !hasAttr(got.Attrs, imap.MailboxAttrNonExistent) {
		t.Errorf("deleted-but-subscribed %q should carry \\NonExistent; attrs=%v", name, got.Attrs)
	}
}

// TestIMAP_RenameMovesSubscription verifies the subscription follows a mailbox
// rename (old name no longer subscribed; new name is, as a live mailbox).
func TestIMAP_RenameMovesSubscription(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	const oldName, newName = "RenSubSrc", "RenSubDst"
	if err := c.Create(oldName, nil).Wait(); err != nil {
		t.Fatalf("CREATE failed: %v", err)
	}
	if err := c.Subscribe(oldName).Wait(); err != nil {
		t.Fatalf("SUBSCRIBE failed: %v", err)
	}
	if err := c.Rename(oldName, newName, nil).Wait(); err != nil {
		t.Fatalf("RENAME failed: %v", err)
	}
	defer func() { c.Delete(newName).Wait() }()

	all := listSubscribed(t, c, "*")
	if got := findSub(all, newName); got == nil {
		t.Errorf("subscription did not follow rename to %q; subscribed=%v", newName, all)
	} else if hasAttr(got.Attrs, imap.MailboxAttrNonExistent) {
		t.Errorf("renamed live mailbox %q wrongly \\NonExistent", newName)
	}
	if got := findSub(all, oldName); got != nil {
		t.Errorf("old name %q still subscribed after rename: %v", oldName, got)
	}
}
