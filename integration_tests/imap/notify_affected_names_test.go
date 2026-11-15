//go:build integration

package imap_test

import (
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/sora/integration_tests/common"
)

// TestNotifyMailboxNameAffectedNames checks the names a MailboxName watch hears
// about when another connection renames a mailbox with a child and creates a
// mailbox under an existing one. RFC 5465 section 5.4: "If a mailbox is
// created or deleted, the mailbox itself and its direct parent (whether it is
// an existing mailbox or not) are considered to be affected." and "When a
// mailbox is renamed, its children are renamed too. No additional MailboxName
// events are sent for children in this case."
func TestNotifyMailboxNameAffectedNames(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	other := notifyLoginAndSelect(t, server.Address, account, nil, "")
	defer other.Logout()
	for _, name := range []string{"Old/Kid", "Parent"} {
		if err := other.Create(name, nil).Wait(); err != nil {
			t.Fatalf("Create(%q) = %v", name, err)
		}
	}

	rec := newNotifyRecorder()
	watcher := notifyLoginAndSelect(t, server.Address, account, rec.options(), "")
	defer watcher.Logout()
	// OLDNAME is sent to IMAP4rev2 clients only.
	if _, err := watcher.Enable(imap.CapIMAP4rev2).Wait(); err != nil {
		t.Fatalf("Enable(IMAP4rev2) = %v", err)
	}
	cmd, err := watcher.Notify(&imap.NotifyOptions{
		Items: []imap.NotifyItem{{
			MailboxSpec: imap.NotifyMailboxSpecPersonal,
			Events:      []imap.NotifyEvent{imap.NotifyEventMailboxName},
		}},
	})
	if err != nil {
		t.Fatalf("Notify() = %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Notify().Wait() = %v", err)
	}

	if err := other.Rename("Old", "Attic/Old", nil).Wait(); err != nil {
		t.Fatalf("Rename() = %v", err)
	}
	if err := other.Create("Parent/Child", nil).Wait(); err != nil {
		t.Fatalf("Create(Parent/Child) = %v", err)
	}

	// Collect LIST responses until every expected name has arrived, then for
	// a few more poll intervals to catch any that should not be sent.
	want := []string{"Attic", "Attic/Old", "Parent/Child", "Parent"}
	got := make(map[string]*imap.ListData)
	deadline := time.After(15 * time.Second)
	var settle <-chan time.Time
collect:
	for {
		select {
		case data := <-rec.list:
			if prev, dup := got[data.Mailbox]; dup {
				t.Errorf("LIST for %q sent twice: %+v and %+v", data.Mailbox, prev, data)
			}
			got[data.Mailbox] = data
			if settle == nil && hasAllNames(got, want) {
				settle = time.After(4 * notifyTestPollInterval)
			}
		case <-settle:
			break collect
		case <-deadline:
			break collect
		}
	}

	for _, name := range want {
		if got[name] == nil {
			t.Errorf("no LIST for %q", name)
		}
	}
	for name, data := range got {
		switch name {
		case "Attic", "Attic/Old", "Parent/Child", "Parent":
		default:
			t.Errorf("unexpected LIST for %q: %+v", name, data)
		}
	}
	if data := got["Attic/Old"]; data != nil && data.OldName != "Old" {
		t.Errorf("LIST for Attic/Old has OLDNAME %q, want \"Old\"", data.OldName)
	}
	if data := got["Parent"]; data != nil {
		if listHasAttr(data, imap.MailboxAttrNonExistent) {
			t.Errorf("LIST for the existing parent carries \\NonExistent: %+v", data.Attrs)
		}
		if !listHasAttr(data, imap.MailboxAttrHasChildren) {
			t.Errorf("LIST for the parent of the created mailbox lacks \\HasChildren: %+v", data.Attrs)
		}
	}
}

func hasAllNames(got map[string]*imap.ListData, names []string) bool {
	for _, name := range names {
		if got[name] == nil {
			return false
		}
	}
	return true
}
