//go:build integration

package imap_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	imapsrv "github.com/migadu/sora/server/imap"
)

func init() {
	// Tick fast so asynchronous notifications arrive within test timeouts;
	// production runs at the IDLE cadence (15s).
	imapsrv.SetNotifyPollIntervalForTests(300 * time.Millisecond)
}

const notifyTestMessage = "From: sender@example.com\r\n" +
	"To: recipient@example.com\r\n" +
	"Subject: NOTIFY integration test\r\n" +
	"\r\n" +
	"body\r\n"

type notifyRecorder struct {
	status   chan *imap.StatusData
	list     chan *imap.ListData
	exists   chan uint32
	expunge  chan uint32
	overflow chan struct{}
}

func newNotifyRecorder() *notifyRecorder {
	return &notifyRecorder{
		status:   make(chan *imap.StatusData, 64),
		list:     make(chan *imap.ListData, 64),
		exists:   make(chan uint32, 64),
		expunge:  make(chan uint32, 64),
		overflow: make(chan struct{}, 4),
	}
}

func (r *notifyRecorder) options() *imapclient.Options {
	return &imapclient.Options{
		UnilateralDataHandler: &imapclient.UnilateralDataHandler{
			Status:  func(data *imap.StatusData) { r.status <- data },
			List:    func(data *imap.ListData) { r.list <- data },
			Expunge: func(seqNum uint32) { r.expunge <- seqNum },
			Mailbox: func(data *imapclient.UnilateralDataMailbox) {
				if data.NumMessages != nil {
					r.exists <- *data.NumMessages
				}
			},
			NotificationOverflow: func() {
				select {
				case r.overflow <- struct{}{}:
				default:
				}
			},
		},
	}
}

// waitStatus waits for an unsolicited STATUS for the given mailbox.
func (r *notifyRecorder) waitStatus(t *testing.T, mailbox string, timeout time.Duration) *imap.StatusData {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case data := <-r.status:
			if strings.EqualFold(data.Mailbox, mailbox) {
				return data
			}
			t.Logf("ignoring STATUS for %q while waiting for %q", data.Mailbox, mailbox)
		case <-deadline:
			t.Fatalf("timeout waiting for unsolicited STATUS for %q", mailbox)
		}
	}
}

// waitList waits for an unsolicited LIST for the given mailbox.
func (r *notifyRecorder) waitList(t *testing.T, mailbox string, timeout time.Duration) *imap.ListData {
	t.Helper()
	return r.waitListMatch(t, mailbox, func(*imap.ListData) bool { return true }, timeout)
}

// waitListMatch waits for an unsolicited LIST for the given mailbox that
// satisfies the predicate, discarding non-matching LIST responses.
func (r *notifyRecorder) waitListMatch(t *testing.T, mailbox string, match func(*imap.ListData) bool, timeout time.Duration) *imap.ListData {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case data := <-r.list:
			if strings.EqualFold(data.Mailbox, mailbox) && match(data) {
				return data
			}
			t.Logf("ignoring LIST for %q while waiting for %q", data.Mailbox, mailbox)
		case <-deadline:
			t.Fatalf("timeout waiting for unsolicited LIST for %q", mailbox)
		}
	}
}

func listHasAttr(data *imap.ListData, attr imap.MailboxAttr) bool {
	for _, a := range data.Attrs {
		if a == attr {
			return true
		}
	}
	return false
}

func notifyLoginAndSelect(t *testing.T, address string, account common.TestAccount, options *imapclient.Options, mailbox string) *imapclient.Client {
	t.Helper()
	client, err := imapclient.DialInsecure(address, options)
	if err != nil {
		t.Fatalf("DialInsecure() = %v", err)
	}
	if err := client.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login() = %v", err)
	}
	if mailbox != "" {
		if _, err := client.Select(mailbox, nil).Wait(); err != nil {
			t.Fatalf("Select(%q) = %v", mailbox, err)
		}
	}
	return client
}

func notifyAppend(t *testing.T, client *imapclient.Client, mailbox string) {
	t.Helper()
	cmd := client.Append(mailbox, int64(len(notifyTestMessage)), nil)
	if _, err := cmd.Write([]byte(notifyTestMessage)); err != nil {
		t.Fatalf("Append().Write() = %v", err)
	}
	if err := cmd.Close(); err != nil {
		t.Fatalf("Append().Close() = %v", err)
	}
	if _, err := cmd.Wait(); err != nil {
		t.Fatalf("Append().Wait() = %v", err)
	}
}

// TestNotifyStatusOnOtherMailboxChange is the core multi-connection NOTIFY
// flow: a watcher with a PERSONAL watch receives unsolicited STATUS when
// another connection changes a non-selected mailbox, plus the initial STATUS
// responses of NOTIFY SET STATUS, and silence after NOTIFY NONE.
func TestNotifyStatusOnOtherMailboxChange(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rec := newNotifyRecorder()
	watcher := notifyLoginAndSelect(t, server.Address, account, rec.options(), "INBOX")
	defer watcher.Logout()

	if !watcher.Caps().Has(imap.CapNotify) {
		t.Fatal("NOTIFY capability not advertised")
	}

	other := notifyLoginAndSelect(t, server.Address, account, nil, "")
	defer other.Logout()
	if err := other.Create("NotifyArchive", nil).Wait(); err != nil {
		t.Fatalf("Create(NotifyArchive) = %v", err)
	}

	// NOTIFY SET STATUS (PERSONAL ...): initial STATUS responses for
	// non-selected mailboxes with message events are due before the tagged
	// OK (RFC 5465 §3.1).
	cmd, err := watcher.Notify(&imap.NotifyOptions{
		Status: true,
		Items: []imap.NotifyItem{
			{
				MailboxSpec: imap.NotifyMailboxSpecPersonal,
				Events: []imap.NotifyEvent{
					imap.NotifyEventMessageNew,
					imap.NotifyEventMessageExpunge,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Notify() = %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Notify().Wait() = %v", err)
	}
	initial := rec.waitStatus(t, "NotifyArchive", 5*time.Second)
	if initial.NumMessages == nil || *initial.NumMessages != 0 {
		t.Errorf("initial STATUS NumMessages = %v, want 0", initial.NumMessages)
	}

	// External change from another connection: unsolicited STATUS within a
	// couple of poll ticks.
	notifyAppend(t, other, "NotifyArchive")
	data := rec.waitStatus(t, "NotifyArchive", 15*time.Second)
	if data.NumMessages == nil || *data.NumMessages != 1 {
		t.Errorf("STATUS NumMessages = %v, want 1", data.NumMessages)
	}
	if data.UIDNext == 0 {
		t.Errorf("STATUS UIDNEXT missing: %+v", data)
	}

	// NOTIFY NONE stops delivery.
	cmd, err = watcher.Notify(nil)
	if err != nil {
		t.Fatalf("Notify(nil) = %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("NotifyNone.Wait() = %v", err)
	}
	notifyAppend(t, other, "NotifyArchive")
	select {
	case data := <-rec.status:
		t.Fatalf("unexpected STATUS for %q after NOTIFY NONE", data.Mailbox)
	case <-time.After(2 * time.Second):
		// expected: nothing
	}
}

// TestNotifySelectedMessageNew verifies asynchronous EXISTS delivery for the
// selected mailbox between commands, driven by another connection's APPEND.
func TestNotifySelectedMessageNew(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rec := newNotifyRecorder()
	watcher := notifyLoginAndSelect(t, server.Address, account, rec.options(), "INBOX")
	defer watcher.Logout()

	cmd, err := watcher.Notify(&imap.NotifyOptions{
		Items: []imap.NotifyItem{
			{
				MailboxSpec: imap.NotifyMailboxSpecSelected,
				Events: []imap.NotifyEvent{
					imap.NotifyEventMessageNew,
					imap.NotifyEventMessageExpunge,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Notify() = %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Notify().Wait() = %v", err)
	}

	other := notifyLoginAndSelect(t, server.Address, account, nil, "")
	defer other.Logout()
	notifyAppend(t, other, "INBOX")

	select {
	case n := <-rec.exists:
		if n != 1 {
			t.Errorf("EXISTS = %v, want 1", n)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for unsolicited EXISTS on the selected mailbox")
	}
}

// TestNotifyMailboxTreeEvents verifies MailboxName and SubscriptionChange
// delivery via unsolicited LIST responses for create, rename, delete and
// unsubscribe performed on another connection.
func TestNotifyMailboxTreeEvents(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rec := newNotifyRecorder()
	watcher := notifyLoginAndSelect(t, server.Address, account, rec.options(), "INBOX")
	defer watcher.Logout()

	cmd, err := watcher.Notify(&imap.NotifyOptions{
		Items: []imap.NotifyItem{
			{
				MailboxSpec: imap.NotifyMailboxSpecPersonal,
				Events: []imap.NotifyEvent{
					imap.NotifyEventMailboxName,
					imap.NotifyEventSubscriptionChange,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Notify() = %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Notify().Wait() = %v", err)
	}

	other := notifyLoginAndSelect(t, server.Address, account, nil, "")
	defer other.Logout()

	// CREATE → LIST for the new name.
	if err := other.Create("NotifyTree", nil).Wait(); err != nil {
		t.Fatalf("Create() = %v", err)
	}
	rec.waitList(t, "NotifyTree", 15*time.Second)

	// RENAME → LIST for the new name.
	if err := other.Rename("NotifyTree", "NotifyTreeRenamed", nil).Wait(); err != nil {
		t.Fatalf("Rename() = %v", err)
	}
	rec.waitList(t, "NotifyTreeRenamed", 15*time.Second)

	// DELETE → LIST with \NonExistent.
	if err := other.Delete("NotifyTreeRenamed").Wait(); err != nil {
		t.Fatalf("Delete() = %v", err)
	}
	deleted := rec.waitList(t, "NotifyTreeRenamed", 15*time.Second)
	if !listHasAttr(deleted, imap.MailboxAttrNonExistent) {
		t.Errorf("LIST for deleted mailbox lacks \\NonExistent: %+v", deleted.Attrs)
	}

	// SUBSCRIBE → LIST with \Subscribed. A fresh non-default mailbox starts
	// unsubscribed (sora keeps default mailboxes permanently subscribed and
	// ignores UNSUBSCRIBE on them, so those never flip). The CREATE and the
	// SUBSCRIBE may land in the same poll tick and coalesce into a single
	// created-mailbox LIST already carrying \Subscribed — wait by predicate.
	if err := other.Create("NotifySubbed", nil).Wait(); err != nil {
		t.Fatalf("Create() = %v", err)
	}
	if err := other.Subscribe("NotifySubbed").Wait(); err != nil {
		t.Fatalf("Subscribe() = %v", err)
	}
	rec.waitListMatch(t, "NotifySubbed", func(data *imap.ListData) bool {
		return listHasAttr(data, imap.MailboxAttrSubscribed)
	}, 15*time.Second)

	// UNSUBSCRIBE → LIST without \Subscribed.
	if err := other.Unsubscribe("NotifySubbed").Wait(); err != nil {
		t.Fatalf("Unsubscribe() = %v", err)
	}
	rec.waitListMatch(t, "NotifySubbed", func(data *imap.ListData) bool {
		return !listHasAttr(data, imap.MailboxAttrSubscribed)
	}, 15*time.Second)
}

// TestNotifyBadEvent verifies that an unsupported event yields a tagged NO
// with the BADEVENT response code listing the supported events.
func TestNotifyBadEvent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	client := notifyLoginAndSelect(t, server.Address, account, nil, "INBOX")
	defer client.Logout()

	cmd, err := client.Notify(&imap.NotifyOptions{
		Items: []imap.NotifyItem{
			{
				MailboxSpec: imap.NotifyMailboxSpecSelected,
				Events: []imap.NotifyEvent{
					imap.NotifyEventMessageNew,
					imap.NotifyEventMessageExpunge,
					imap.NotifyEventAnnotationChange,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Notify() = %v", err)
	}
	err = cmd.Wait()
	if err == nil {
		t.Fatal("Notify().Wait() succeeded, want NO [BADEVENT ...]")
	}
	var imapErr *imap.Error
	if !errors.As(err, &imapErr) {
		t.Fatalf("Notify().Wait() = %v, want *imap.Error", err)
	}
	if imapErr.Type != imap.StatusResponseTypeNo {
		t.Errorf("status response type = %v, want NO", imapErr.Type)
	}
	if imapErr.Code != imap.ResponseCodeBadEvent {
		t.Errorf("response code = %v, want BADEVENT", imapErr.Code)
	}
}

// TestNotifyOverflow verifies that when a single tick observes more changed
// mailboxes than the cap, the watch is dropped with NOTIFICATIONOVERFLOW
// (RFC 5465 §5.8) and the connection stays usable afterwards.
func TestNotifyOverflow(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Small cap so a handful of already-watched mailboxes changing in one tick
	// trips overflow deterministically.
	imapsrv.SetNotifyMaxChangedMailboxesForTests(3)
	defer imapsrv.SetNotifyMaxChangedMailboxesForTests(100)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Create the mailboxes up front so they are already in the watched
	// (initialized) set before any of them change — a mailbox entering the
	// matched set is initialized, not reported, so it must pre-exist to count
	// as "changed" and contribute to overflow.
	other := notifyLoginAndSelect(t, server.Address, account, nil, "")
	defer other.Logout()
	const nBoxes = 8
	names := make([]string, nBoxes)
	for i := 0; i < nBoxes; i++ {
		names[i] = fmt.Sprintf("Overflow-%03d", i)
		if err := other.Create(names[i], nil).Wait(); err != nil {
			t.Fatalf("Create(%q) = %v", names[i], err)
		}
	}

	rec := newNotifyRecorder()
	watcher := notifyLoginAndSelect(t, server.Address, account, rec.options(), "INBOX")
	defer watcher.Logout()

	cmd, err := watcher.Notify(&imap.NotifyOptions{
		Items: []imap.NotifyItem{
			{
				MailboxSpec: imap.NotifyMailboxSpecPersonal,
				Events: []imap.NotifyEvent{
					imap.NotifyEventMessageNew,
					imap.NotifyEventMessageExpunge,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Notify() = %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Notify().Wait() = %v", err)
	}

	// Deliver to every mailbox in a burst so a single tick sees them all
	// change at once, exceeding the cap.
	for _, name := range names {
		notifyAppend(t, other, name)
	}

	select {
	case <-rec.overflow:
		// expected
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for NOTIFICATIONOVERFLOW")
	}

	// The connection must remain usable after overflow (behave as NOTIFY NONE).
	if err := watcher.Noop().Wait(); err != nil {
		t.Fatalf("Noop() after overflow = %v", err)
	}
	// Re-arming NOTIFY must succeed.
	cmd, err = watcher.Notify(&imap.NotifyOptions{
		Items: []imap.NotifyItem{
			{
				MailboxSpec: imap.NotifyMailboxSpecSelected,
				Events:      []imap.NotifyEvent{imap.NotifyEventMessageNew, imap.NotifyEventMessageExpunge},
			},
		},
	})
	if err != nil {
		t.Fatalf("re-arm Notify() = %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("re-arm Notify().Wait() = %v", err)
	}
}

// TestNotifySelectedDelayedDuringIdle exercises the SELECTED-DELAYED /
// IDLE interaction (RFC 5465 §6.1.2): an expunge from another connection must
// be delivered while the watcher is idling (IDLE is a sync point), and a
// subsequent new message's EXISTS must not be starved behind it.
func TestNotifySelectedDelayedDuringIdle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Seed two messages so there is something to expunge.
	seed := notifyLoginAndSelect(t, server.Address, account, nil, "")
	for i := 0; i < 2; i++ {
		notifyAppend(t, seed, "INBOX")
	}
	seed.Logout()

	rec := newNotifyRecorder()
	watcher := notifyLoginAndSelect(t, server.Address, account, rec.options(), "INBOX")
	defer watcher.Logout()

	cmd, err := watcher.Notify(&imap.NotifyOptions{
		Items: []imap.NotifyItem{
			{
				MailboxSpec: imap.NotifyMailboxSpecSelectedDelayed,
				Events:      []imap.NotifyEvent{imap.NotifyEventMessageNew, imap.NotifyEventMessageExpunge},
			},
		},
	})
	if err != nil {
		t.Fatalf("Notify() = %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Notify().Wait() = %v", err)
	}

	// Enter IDLE; the pump keeps ticking and (per §6.1.2) IDLE is a sync point
	// where delayed expunges are released.
	idleCmd, err := watcher.Idle()
	if err != nil {
		t.Fatalf("Idle() = %v", err)
	}

	// Another connection expunges message 1, then delivers a new message.
	other := notifyLoginAndSelect(t, server.Address, account, nil, "INBOX")
	defer other.Logout()
	storeCmd := other.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:     imap.StoreFlagsAdd,
		Silent: true,
		Flags:  []imap.Flag{imap.FlagDeleted},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("Store() = %v", err)
	}
	if err := other.Expunge().Close(); err != nil {
		t.Fatalf("Expunge() = %v", err)
	}

	// The expunge must be delivered during IDLE.
	select {
	case seqNum := <-rec.expunge:
		if seqNum != 1 {
			t.Errorf("EXPUNGE seqnum = %v, want 1", seqNum)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for EXPUNGE during IDLE (SELECTED-DELAYED sync point)")
	}

	// A subsequent delivery's EXISTS must not be starved behind the expunge.
	notifyAppend(t, other, "INBOX")
	select {
	case <-rec.exists:
		// expected
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for EXISTS after expunge during IDLE")
	}

	if err := idleCmd.Close(); err != nil {
		t.Fatalf("idle DONE = %v", err)
	}
}
