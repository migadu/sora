//go:build integration

package imap_test

import (
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/integration_tests/common"
)

// A watched descendant keeps the one ancestor rename observable even when
// the ancestor itself is unsubscribed; no redundant carried-child rename is sent.
func TestNotifySubscribedDescendantRenameIsCoalesced(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	for _, tc := range []struct{ name, leaf string }{
		{"child", "Old/Kid"}, {"grandchild", "Old/Mid/Grand"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, account := common.SetupIMAPServer(t)
			defer srv.Close()
			other := notifyLoginAndSelect(t, srv.Address, account, nil, "")
			defer other.Logout()
			if err := other.Create(tc.leaf, nil).Wait(); err != nil {
				t.Fatal(err)
			}
			for _, parent := range []string{"Old", "Old/Mid"} {
				if parent == "Old/Mid" && tc.name != "grandchild" {
					continue
				}
				if err := other.Unsubscribe(parent).Wait(); err != nil {
					t.Fatal(err)
				}
			}
			if err := other.Subscribe(tc.leaf).Wait(); err != nil {
				t.Fatal(err)
			}
			rec := newNotifyRecorder()
			watcher := notifyLoginAndSelect(t, srv.Address, account, rec.options(), "")
			defer watcher.Logout()
			if _, err := watcher.Enable(imap.CapIMAP4rev2).Wait(); err != nil {
				t.Fatal(err)
			}
			cmd, err := watcher.Notify(&imap.NotifyOptions{Items: []imap.NotifyItem{{MailboxSpec: imap.NotifyMailboxSpecSubscribed, Events: []imap.NotifyEvent{imap.NotifyEventMailboxName}}}})
			if err != nil {
				t.Fatal(err)
			}
			if err = cmd.Wait(); err != nil {
				t.Fatal(err)
			}
			if err = other.Rename("Old", "New", nil).Wait(); err != nil {
				t.Fatal(err)
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
			if len(got) != 1 || got[0].Mailbox != "New" || got[0].OldName != "Old" {
				t.Fatalf("got %+v, want only New OLDNAME Old", got)
			}
			if listHasAttr(got[0], imap.MailboxAttrSubscribed) {
				t.Errorf("unsubscribed ancestor labeled subscribed: %+v", got[0])
			}
		})
	}
}
