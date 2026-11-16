//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
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

// TestNotifyLaggingReplicaShrinkUsesPrimary is the other side of the guard:
// the read pool falls far behind (here it shows none of the account's
// mailboxes, as after a failover to a replica that has not replayed them).
// That view must not be diffed into LIST \NonExistent for mailboxes that
// still exist, and it must not silence the watch either: the pump takes the
// primary's view, so a real deletion made meanwhile is reported, and only it,
// and a new message in another mailbox still arrives as STATUS. Before the
// fix every tick was skipped while the replica lagged.
func TestNotifyLaggingReplicaShrinkUsesPrimary(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	other := notifyLoginAndSelect(t, server.Address, account, nil, "")
	defer other.Logout()
	if err := other.Create("Doomed", nil).Wait(); err != nil {
		t.Fatalf("Create(Doomed) = %v", err)
	}

	// The replica starts out current: a copy of the mailboxes as they are now.
	// It is installed before the watcher connects, so no NOTIFY pump is
	// running while the read pool is swapped (and the watcher's logout,
	// deferred later, runs before the swap back).
	defer installLaggingReplica(t, server, nil, []string{"mailboxes"}, false)()
	database := server.ResilientDB.GetOperationalDatabase()
	var replicaSchema string
	if err := database.ReadPool.QueryRow(context.Background(), "SELECT current_schema()").Scan(&replicaSchema); err != nil {
		t.Fatalf("current_schema() = %v", err)
	}
	if replicaSchema == "public" {
		t.Fatalf("lagging replica reads the public schema")
	}

	rec := newNotifyRecorder()
	watcher := notifyLoginAndSelect(t, server.Address, account, rec.options(), "")
	defer func() {
		// Stop and join the NOTIFY pump before installLaggingReplica restores
		// the test-only read-pool pointer. Logout alone only queues a command.
		cmd, err := watcher.Notify(nil)
		if err == nil {
			err = cmd.Wait()
		}
		if err != nil {
			t.Errorf("stopping NOTIFY before restoring the replica: %v", err)
		}
		_ = watcher.Logout().Wait()
	}()

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

	// The read pool falls far behind: it shows no mailboxes at all.
	if _, err := database.WritePool.Exec(context.Background(),
		"DELETE FROM "+pgx.Identifier{replicaSchema, "mailboxes"}.Sanitize()); err != nil {
		t.Fatalf("emptying the replica's mailboxes = %v", err)
	}
	// Let a few ticks see only the lag, then make real changes on the primary.
	time.Sleep(3 * notifyTestPollInterval)
	if err := other.Delete("Doomed").Wait(); err != nil {
		t.Fatalf("Delete(Doomed) = %v", err)
	}
	notifyAppend(t, other, "INBOX")

	var gotDeleted, gotStatus bool
	deadline := time.After(5 * time.Second)
	for !gotDeleted || !gotStatus {
		select {
		case data := <-rec.list:
			if !strings.EqualFold(data.Mailbox, "Doomed") || !listHasAttr(data, imap.MailboxAttrNonExistent) {
				t.Fatalf("unexpected LIST %q %v: the lagging replica's view was diffed", data.Mailbox, data.Attrs)
			}
			gotDeleted = true
		case data := <-rec.status:
			if !strings.EqualFold(data.Mailbox, "INBOX") {
				t.Fatalf("unexpected STATUS for %q", data.Mailbox)
			}
			if data.NumMessages == nil || *data.NumMessages != 1 {
				t.Fatalf("STATUS INBOX MESSAGES = %v, want 1", data.NumMessages)
			}
			gotStatus = true
		case <-deadline:
			t.Fatalf("watch silenced by the lagging replica: LIST \\NonExistent Doomed received = %v, STATUS INBOX received = %v", gotDeleted, gotStatus)
		}
	}

	// Later ticks, still on the lagging replica, report nothing more.
	select {
	case data := <-rec.list:
		t.Fatalf("unexpected LIST %q %v after the deletion was reported", data.Mailbox, data.Attrs)
	case data := <-rec.status:
		t.Fatalf("unexpected STATUS for %q after the message was reported", data.Mailbox)
	case <-time.After(3 * notifyTestPollInterval):
	}
}
