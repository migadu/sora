//go:build integration

package imap_test

import (
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/integration_tests/common"
)

// TestNotifyRenameOutOfMailboxesAndSubtreeIsReported verifies that renaming a
// watched mailbox (or an ancestor carrying a watched descendant) out of an
// explicit mailboxes or subtree filter still delivers the RFC 5465 §5.4 LIST
// response carrying OLDNAME.
func TestNotifyRenameOutOfMailboxesAndSubtreeIsReported(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Note: "Archive" is a permanent default mailbox on test accounts, so
	// "Archived" is used for the top-level rename while "Archive/Alpha" moves a
	// child under the existing "Archive" folder.
	tests := []struct {
		name      string
		setup     []string
		item      imap.NotifyItem
		from, to  string
		wantName  string
		wantOld   string
	}{
		{
			name:  "mailboxes",
			setup: []string{"Projects"},
			item: imap.NotifyItem{
				Mailboxes: []string{"Projects"},
				Events:    []imap.NotifyEvent{imap.NotifyEventMailboxName},
			},
			from:     "Projects",
			to:       "Archived",
			wantName: "Archived",
			wantOld:  "Projects",
		},
		{
			name:  "subtree",
			setup: []string{"Projects/Alpha"},
			item: imap.NotifyItem{
				Mailboxes: []string{"Projects"},
				Subtree:   true,
				Events:    []imap.NotifyEvent{imap.NotifyEventMailboxName},
			},
			from:     "Projects/Alpha",
			to:       "Archive/Alpha",
			wantName: "Archive/Alpha",
			wantOld:  "Projects/Alpha",
		},
		{
			name:  "carried_mailboxes",
			setup: []string{"Old/Kid"},
			item: imap.NotifyItem{
				Mailboxes: []string{"Old/Kid"},
				Events:    []imap.NotifyEvent{imap.NotifyEventMailboxName},
			},
			from:     "Old",
			to:       "New",
			wantName: "New",
			wantOld:  "Old",
		},
		{
			name:  "carried_subtree",
			setup: []string{"Old/Mid/Grand"},
			item: imap.NotifyItem{
				Mailboxes: []string{"Old/Mid"},
				Subtree:   true,
				Events:    []imap.NotifyEvent{imap.NotifyEventMailboxName},
			},
			from:     "Old",
			to:       "New",
			wantName: "New",
			wantOld:  "Old",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, account := common.SetupIMAPServer(t)
			defer srv.Close()

			other := notifyLoginAndSelect(t, srv.Address, account, nil, "")
			defer other.Logout()
			for _, mbox := range tc.setup {
				if err := other.Create(mbox, nil).Wait(); err != nil {
					t.Fatalf("Create(%q) = %v", mbox, err)
				}
			}

			rec := newNotifyRecorder()
			watcher := notifyLoginAndSelect(t, srv.Address, account, rec.options(), "")
			defer watcher.Logout()

			cmd, err := watcher.Notify(&imap.NotifyOptions{Items: []imap.NotifyItem{tc.item}})
			if err != nil {
				t.Fatalf("Notify() = %v", err)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("Notify().Wait() = %v", err)
			}

			if err := other.Rename(tc.from, tc.to, nil).Wait(); err != nil {
				t.Fatalf("Rename(%q, %q) = %v", tc.from, tc.to, err)
			}

			deadline := time.After(4 * time.Second)
			var settle <-chan time.Time
			var got []*imap.ListData
		collect:
			for {
				select {
				case data := <-rec.list:
					got = append(got, data)
					if settle == nil {
						settle = time.After(4 * notifyTestPollInterval)
					}
				case <-settle:
					break collect
				case <-deadline:
					break collect
				}
			}

			if len(got) != 1 || got[0].Mailbox != tc.wantName || got[0].OldName != tc.wantOld {
				t.Fatalf("got LIST responses %+v, want single %q OLDNAME %q", got, tc.wantName, tc.wantOld)
			}
		})
	}
}

// TestNotifySubscribedWatchReportsUnsubscribe verifies that a watch using the
// SUBSCRIBED mailbox specifier with SubscriptionChange receives the unsolicited
// LIST without \Subscribed when a subscribed mailbox is unsubscribed (RFC 5465
// §5.5, §6.4), and with \Subscribed when it is subscribed again.
func TestNotifySubscribedWatchReportsUnsubscribe(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	srv, account := common.SetupIMAPServer(t)
	defer srv.Close()

	other := notifyLoginAndSelect(t, srv.Address, account, nil, "")
	defer other.Logout()

	if err := other.Create("News", nil).Wait(); err != nil {
		t.Fatalf("Create(News) = %v", err)
	}
	if err := other.Subscribe("News").Wait(); err != nil {
		t.Fatalf("Subscribe(News) = %v", err)
	}

	rec := newNotifyRecorder()
	watcher := notifyLoginAndSelect(t, srv.Address, account, rec.options(), "")
	defer watcher.Logout()

	cmd, err := watcher.Notify(&imap.NotifyOptions{
		Items: []imap.NotifyItem{{
			MailboxSpec: imap.NotifyMailboxSpecSubscribed,
			Events:      []imap.NotifyEvent{imap.NotifyEventSubscriptionChange},
		}},
	})
	if err != nil {
		t.Fatalf("Notify() = %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Notify().Wait() = %v", err)
	}

	if err := other.Unsubscribe("News").Wait(); err != nil {
		t.Fatalf("Unsubscribe(News) = %v", err)
	}

	select {
	case data := <-rec.list:
		if data.Mailbox != "News" {
			t.Fatalf("got LIST for %q, want \"News\"", data.Mailbox)
		}
		if listHasAttr(data, imap.MailboxAttrSubscribed) {
			t.Fatalf("LIST after UNSUBSCRIBE unexpectedly carries \\Subscribed: %+v", data.Attrs)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timeout waiting for unsolicited LIST on UNSUBSCRIBE under SUBSCRIBED watch")
	}

	if err := other.Subscribe("News").Wait(); err != nil {
		t.Fatalf("Subscribe(News) = %v", err)
	}

	select {
	case data := <-rec.list:
		if data.Mailbox != "News" {
			t.Fatalf("got LIST for %q, want \"News\"", data.Mailbox)
		}
		if !listHasAttr(data, imap.MailboxAttrSubscribed) {
			t.Fatalf("LIST after SUBSCRIBE lacks \\Subscribed: %+v", data.Attrs)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timeout waiting for unsolicited LIST on SUBSCRIBE under SUBSCRIBED watch")
	}
}
