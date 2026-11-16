package imap

import (
	"context"
	"io"
	"log"
	"net"
	"slices"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/go-imap/imapserver"
)

type notifyDiffTestSession struct {
	*meteredSession
	prev       map[int64]notifySnapshotEntry
	cur        map[int64]notifySnapshotEntry
	sharedRoot string
}

func (s *notifyDiffTestSession) SetNotify(_ context.Context, options *imap.NotifyOptions, w *imapserver.UpdateWriter) error {
	watch := newTestWatch(options.Items...)
	watch.snapshot = s.prev
	return s.IMAPSession.notifyWriteTreeEvents(watch, diffNotifySnapshots(watch.snapshot, s.cur), s.sharedRoot, w)
}

func (s *notifyDiffTestSession) NotifyPoll(_ context.Context, _ *imapserver.UpdateWriter, stop <-chan struct{}) error {
	<-stop
	return nil
}

func runNotifyDiffSnapshots(
	t *testing.T,
	items []imap.NotifyItem,
	prev, cur map[int64]notifySnapshotEntry,
	sharedRoot string,
) []*imap.ListData {
	t.Helper()

	srv := newDisabledCapsTestServer(t, IMAPServerOptions{})
	is := imapserver.New(&imapserver.Options{
		NewSession: func(c *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			sess, _, err := srv.newSession(c)
			if err != nil {
				return nil, nil, err
			}
			return &notifyDiffTestSession{
				meteredSession: sess.(*meteredSession),
				prev:           keyedSnapshot(prev),
				cur:            keyedSnapshot(cur),
				sharedRoot:     sharedRoot,
			}, &imapserver.GreetingData{PreAuth: true}, nil
		},
		Logger:       log.New(io.Discard, "", 0),
		InsecureAuth: true,
		Caps:         srv.caps,
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go is.Serve(ln)
	t.Cleanup(func() { _ = is.Close() })

	var got []*imap.ListData
	client, err := imapclient.DialInsecure(ln.Addr().String(), &imapclient.Options{
		UnilateralDataHandler: &imapclient.UnilateralDataHandler{
			List: func(data *imap.ListData) {
				got = append(got, data)
			},
		},
	})
	if err != nil {
		t.Fatalf("DialInsecure: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	cmd, err := client.Notify(&imap.NotifyOptions{Items: items})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Notify.Wait: %v", err)
	}
	return got
}

func TestNotifyDiffSnapshotsFilterExitAndSubscriptionChange(t *testing.T) {
	type wantList struct {
		mailbox    string
		oldName    string
		subscribed bool
	}

	tests := []struct {
		name      string
		items     []imap.NotifyItem
		prev, cur map[int64]notifySnapshotEntry
		want      []wantList
	}{
		{
			name: "MailboxesRenameOutEmitsOldName",
			items: []imap.NotifyItem{{
				Mailboxes: []string{"Projects"},
				Events:    []imap.NotifyEvent{imap.NotifyEventMailboxName},
			}},
			prev: map[int64]notifySnapshotEntry{
				1:  {name: "Projects"},
				99: {name: "UnrelatedA"},
			},
			cur: map[int64]notifySnapshotEntry{
				1:  {name: "Archive"},
				99: {name: "UnrelatedB"},
			},
			want: []wantList{{mailbox: "Archive", oldName: "Projects"}},
		},
		{
			name: "SubtreeRenameOutEmitsOldName",
			items: []imap.NotifyItem{{
				Mailboxes: []string{"Projects"},
				Subtree:   true,
				Events:    []imap.NotifyEvent{imap.NotifyEventMailboxName},
			}},
			prev: map[int64]notifySnapshotEntry{
				1:  {name: "Projects"},
				2:  {name: "Projects/Alpha"},
				99: {name: "UnrelatedA"},
			},
			cur: map[int64]notifySnapshotEntry{
				1:  {name: "Projects"},
				2:  {name: "Archive/Alpha"},
				99: {name: "UnrelatedB"},
			},
			want: []wantList{{mailbox: "Archive/Alpha", oldName: "Projects/Alpha"}},
		},
		{
			name: "MailboxesCarriedDescendantRenameOutEmitsCoalescedAncestor",
			items: []imap.NotifyItem{{
				Mailboxes: []string{"Old/Kid"},
				Events:    []imap.NotifyEvent{imap.NotifyEventMailboxName},
			}},
			prev: map[int64]notifySnapshotEntry{
				1: {name: "Old"},
				2: {name: "Old/Kid"},
			},
			cur: map[int64]notifySnapshotEntry{
				1: {name: "New"},
				2: {name: "New/Kid"},
			},
			want: []wantList{{mailbox: "New", oldName: "Old"}},
		},
		{
			name: "SubtreeCarriedDescendantRenameOutEmitsCoalescedAncestor",
			items: []imap.NotifyItem{{
				Mailboxes: []string{"Old/Mid"},
				Subtree:   true,
				Events:    []imap.NotifyEvent{imap.NotifyEventMailboxName},
			}},
			prev: map[int64]notifySnapshotEntry{
				1: {name: "Old"},
				2: {name: "Old/Mid/Grand"},
			},
			cur: map[int64]notifySnapshotEntry{
				1: {name: "New"},
				2: {name: "New/Mid/Grand"},
			},
			want: []wantList{{mailbox: "New", oldName: "Old"}},
		},
		{
			name: "SubscribedWatchReportsUnsubscribeWithoutSubscribedAttr",
			items: []imap.NotifyItem{{
				MailboxSpec: imap.NotifyMailboxSpecSubscribed,
				Events:      []imap.NotifyEvent{imap.NotifyEventSubscriptionChange},
			}},
			prev: map[int64]notifySnapshotEntry{
				1: {name: "News", subscribed: true},
				2: {name: "UnsubDeleted", subscribed: false},
			},
			cur: map[int64]notifySnapshotEntry{
				1: {name: "News", subscribed: false},
				3: {name: "UnsubCreated", subscribed: false},
			},
			want: []wantList{{mailbox: "News", subscribed: false}},
		},
		{
			name: "PersonalSubscriptionChangeOnSameTickRenameOmitsOldName",
			items: []imap.NotifyItem{{
				MailboxSpec: imap.NotifyMailboxSpecPersonal,
				Events:      []imap.NotifyEvent{imap.NotifyEventSubscriptionChange},
			}},
			prev: map[int64]notifySnapshotEntry{
				1: {name: "Old", subscribed: false},
			},
			cur: map[int64]notifySnapshotEntry{
				1: {name: "New", subscribed: true},
			},
			want: []wantList{{mailbox: "New", subscribed: true}},
		},
		{
			name: "SubscribedSubscriptionChangeOnSameTickRenameAndUnsubscribeOmitsOldName",
			items: []imap.NotifyItem{{
				MailboxSpec: imap.NotifyMailboxSpecSubscribed,
				Events:      []imap.NotifyEvent{imap.NotifyEventSubscriptionChange},
			}},
			prev: map[int64]notifySnapshotEntry{
				1: {name: "Old", subscribed: true},
			},
			cur: map[int64]notifySnapshotEntry{
				1: {name: "New", subscribed: false},
			},
			want: []wantList{{mailbox: "New", subscribed: false}},
		},
		{
			name: "NegativeControlsNotEmitted",
			items: []imap.NotifyItem{
				{
					Mailboxes: []string{"Projects"},
					Events:    []imap.NotifyEvent{imap.NotifyEventMailboxName},
				},
				{
					MailboxSpec: imap.NotifyMailboxSpecSubscribed,
					Events:      []imap.NotifyEvent{imap.NotifyEventMailboxName, imap.NotifyEventSubscriptionChange},
				},
			},
			prev: map[int64]notifySnapshotEntry{
				1: {name: "UnrelatedA", subscribed: false},
				2: {name: "UnsubDeleted", subscribed: false},
			},
			cur: map[int64]notifySnapshotEntry{
				1: {name: "UnrelatedB", subscribed: false},
				3: {name: "UnsubCreated", subscribed: false},
			},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotData := runNotifyDiffSnapshots(t, tc.items, tc.prev, tc.cur, "")
			var got []wantList
			for _, d := range gotData {
				got = append(got, wantList{
					mailbox:    d.Mailbox,
					oldName:    d.OldName,
					subscribed: slices.Contains(d.Attrs, imap.MailboxAttrSubscribed),
				})
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got LIST responses %+v, want %+v", got, tc.want)
			}
		})
	}
}
