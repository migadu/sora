//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/sora/integration_tests/common"
)

// TestNotifyBulkMailboxDeleteIsReported: another connection deleting more
// than half of the account's mailboxes looks exactly like the signature of a
// lagging read replica the pump guards against (a sharply smaller account
// snapshot). The guard must not silence the watch: the deletions are reported
// as LIST \NonExistent (RFC 5465 §5.4) and later message events in other
// mailboxes still arrive as STATUS (RFC 5465 §5.2, §5.3). Before the fix the
// pump skipped every tick from then on and sent nothing at all.
//
// Both kinds of watcher session are covered: one reading from the read pool,
// and one pinned to the primary by a write of its own.
func TestNotifyBulkMailboxDeleteIsReported(t *testing.T) {
	for _, tc := range []struct {
		name   string
		pinned bool
	}{
		{name: "read pool", pinned: false},
		{name: "pinned to primary", pinned: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)

			server, account := common.SetupIMAPServer(t)
			defer server.Close()

			other := notifyLoginAndSelect(t, server.Address, account, nil, "")
			defer other.Logout()

			rec := newNotifyRecorder()
			watcher := notifyLoginAndSelect(t, server.Address, account, rec.options(), "")
			defer watcher.Logout()

			if tc.pinned {
				// A write of the watcher's own pins its session to the primary.
				if err := watcher.Create("PinnedByWatcher", nil).Wait(); err != nil {
					t.Fatalf("Create(PinnedByWatcher) = %v", err)
				}
			}

			// Grow the account so that deleting the new mailboxes leaves fewer
			// than half of them: base*2 < base+(base+2).
			existing, err := other.List("", "*", nil).Collect()
			if err != nil {
				t.Fatalf("List() = %v", err)
			}
			bulk := make([]string, len(existing)+2)
			for i := range bulk {
				bulk[i] = fmt.Sprintf("Bulk%d", i)
				if err := other.Create(bulk[i], nil).Wait(); err != nil {
					t.Fatalf("Create(%s) = %v", bulk[i], err)
				}
			}

			cmd, err := watcher.Notify(&imap.NotifyOptions{
				Items: []imap.NotifyItem{{
					MailboxSpec: imap.NotifyMailboxSpecPersonal,
					Events: []imap.NotifyEvent{
						imap.NotifyEventMessageNew,
						imap.NotifyEventMessageExpunge,
						imap.NotifyEventMailboxName,
					},
				}},
			})
			if err != nil {
				t.Fatalf("Notify() = %v", err)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("Notify().Wait() = %v", err)
			}

			for _, name := range bulk {
				if err := other.Delete(name).Wait(); err != nil {
					t.Fatalf("Delete(%s) = %v", name, err)
				}
			}

			// The LIST responses of one tick come in no particular order.
			pending := make(map[string]bool, len(bulk))
			for _, name := range bulk {
				pending[strings.ToLower(name)] = true
			}
			deadline := time.After(5 * time.Second)
			for len(pending) > 0 {
				select {
				case data := <-rec.list:
					if !listHasAttr(data, imap.MailboxAttrNonExistent) {
						t.Logf("ignoring LIST for %q without \\NonExistent", data.Mailbox)
						continue
					}
					delete(pending, strings.ToLower(data.Mailbox))
				case <-deadline:
					t.Fatalf("no LIST \\NonExistent for %d of %d deleted mailboxes: %v", len(pending), len(bulk), pending)
				}
			}

			// The watch is not wedged: a new message elsewhere is reported.
			notifyAppend(t, other, "INBOX")
			status := rec.waitStatus(t, "INBOX", 5*time.Second)
			if status.NumMessages == nil || *status.NumMessages != 1 {
				t.Errorf("STATUS INBOX MESSAGES = %v, want 1", status.NumMessages)
			}
		})
	}
}
