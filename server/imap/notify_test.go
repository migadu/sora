package imap

import (
	"testing"

	"github.com/emersion/go-imap/v2"
)

func newTestWatch(items ...imap.NotifyItem) *notifyWatch {
	watch := &notifyWatch{options: &imap.NotifyOptions{Items: items}}
	for i := range watch.options.Items {
		item := &watch.options.Items[i]
		if item.MailboxSpec == imap.NotifyMailboxSpecSelected ||
			item.MailboxSpec == imap.NotifyMailboxSpecSelectedDelayed {
			watch.selected = item
			watch.delayed = item.MailboxSpec == imap.NotifyMailboxSpecSelectedDelayed
		}
	}
	return watch
}

func TestNotifyEventsForMailbox(t *testing.T) {
	msgEvents := []imap.NotifyEvent{imap.NotifyEventMessageNew, imap.NotifyEventMessageExpunge}
	treeEvents := []imap.NotifyEvent{imap.NotifyEventMailboxName, imap.NotifyEventSubscriptionChange}

	tests := []struct {
		name       string
		watch      *notifyWatch
		mailbox    string
		subscribed bool
		sharedRoot string
		want       []imap.NotifyEvent
	}{
		{
			name:    "PersonalMatchesEverything",
			watch:   newTestWatch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecPersonal, Events: msgEvents}),
			mailbox: "Lists/Lemonade",
			want:    msgEvents,
		},
		{
			name:       "PersonalExcludesSharedNamespace",
			watch:      newTestWatch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecPersonal, Events: msgEvents}),
			mailbox:    "Shared/Team",
			sharedRoot: "Shared",
			want:       nil,
		},
		{
			name:    "InboxesMatchesOnlyInbox",
			watch:   newTestWatch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecInboxes, Events: msgEvents}),
			mailbox: "Archive",
			want:    nil,
		},
		{
			name:    "InboxesMatchesInboxCaseInsensitive",
			watch:   newTestWatch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecInboxes, Events: msgEvents}),
			mailbox: "inbox",
			want:    msgEvents,
		},
		{
			name:       "SubscribedRequiresSubscription",
			watch:      newTestWatch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecSubscribed, Events: msgEvents}),
			mailbox:    "Archive",
			subscribed: false,
			want:       nil,
		},
		{
			name:       "SubscribedMatchesSubscription",
			watch:      newTestWatch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecSubscribed, Events: msgEvents}),
			mailbox:    "Archive",
			subscribed: true,
			want:       msgEvents,
		},
		{
			name:    "MailboxesExactMatch",
			watch:   newTestWatch(imap.NotifyItem{Mailboxes: []string{"Archive"}, Events: msgEvents}),
			mailbox: "Archive",
			want:    msgEvents,
		},
		{
			name:    "MailboxesNoWildcardExpansion",
			watch:   newTestWatch(imap.NotifyItem{Mailboxes: []string{"Archive"}, Events: msgEvents}),
			mailbox: "Archive/2026",
			want:    nil,
		},
		{
			name:    "SubtreeMatchesChildren",
			watch:   newTestWatch(imap.NotifyItem{Mailboxes: []string{"Lists"}, Subtree: true, Events: msgEvents}),
			mailbox: "Lists/Lemonade/Dev",
			want:    msgEvents,
		},
		{
			name:    "SubtreeMatchesRootItself",
			watch:   newTestWatch(imap.NotifyItem{Mailboxes: []string{"Lists"}, Subtree: true, Events: msgEvents}),
			mailbox: "Lists",
			want:    msgEvents,
		},
		{
			name:    "SubtreeDoesNotMatchSiblingPrefix",
			watch:   newTestWatch(imap.NotifyItem{Mailboxes: []string{"Lists"}, Subtree: true, Events: msgEvents}),
			mailbox: "ListsArchive",
			want:    nil,
		},
		{
			name: "EventGroupsAccumulate",
			watch: newTestWatch(
				imap.NotifyItem{Mailboxes: []string{"INBOX"}, Events: msgEvents},
				imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecPersonal, Events: treeEvents},
			),
			mailbox: "INBOX",
			// RFC 5465 section 6: both groups apply, events are the union.
			want: append(append([]imap.NotifyEvent{}, msgEvents...), treeEvents...),
		},
		{
			name: "SelectedSpecifierNeverMatchesByName",
			watch: newTestWatch(
				imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecSelected, Events: msgEvents},
			),
			mailbox: "INBOX",
			want:    nil,
		},
		{
			name:    "NoneEventGroupContributesNothing",
			watch:   newTestWatch(imap.NotifyItem{Mailboxes: []string{"Archive"}, Events: nil}),
			mailbox: "Archive",
			want:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events := tc.watch.eventsForMailbox(tc.mailbox, tc.subscribed, tc.sharedRoot)
			if len(events) != len(tc.want) {
				t.Fatalf("eventsForMailbox(%q) = %v, want %v", tc.mailbox, events, tc.want)
			}
			for _, ev := range tc.want {
				if !events[ev] {
					t.Errorf("eventsForMailbox(%q) is missing %v", tc.mailbox, ev)
				}
			}
		})
	}
}

func TestDiffNotifySnapshots(t *testing.T) {
	prev := map[int64]notifySnapshotEntry{
		1: {name: "INBOX", subscribed: true},
		2: {name: "Old", subscribed: false},
		3: {name: "Doomed", subscribed: false},
		4: {name: "Stable", subscribed: false},
	}
	cur := map[int64]notifySnapshotEntry{
		1: {name: "INBOX", subscribed: true},   // unchanged
		2: {name: "New", subscribed: false},    // renamed
		4: {name: "Stable", subscribed: true},  // subscription flip
		5: {name: "Created", subscribed: true}, // created
		// 3 deleted
	}

	events := diffNotifySnapshots(prev, cur)

	byName := make(map[string]notifyTreeEvent)
	for _, ev := range events {
		byName[ev.name] = ev
	}
	if len(events) != 4 {
		t.Fatalf("diffNotifySnapshots produced %d events (%v), want 4", len(events), byName)
	}

	if ev := byName["New"]; ev.event != imap.NotifyEventMailboxName || ev.oldName != "Old" || ev.deleted {
		t.Errorf("rename event wrong: %+v", ev)
	}
	if ev := byName["Doomed"]; ev.event != imap.NotifyEventMailboxName || !ev.deleted {
		t.Errorf("delete event wrong: %+v", ev)
	}
	if ev := byName["Created"]; ev.event != imap.NotifyEventMailboxName || ev.deleted || ev.oldName != "" {
		t.Errorf("create event wrong: %+v", ev)
	}
	if ev := byName["Stable"]; ev.event != imap.NotifyEventSubscriptionChange {
		t.Errorf("subscription event wrong: %+v", ev)
	}
}

func TestNotifyStatusOptions(t *testing.T) {
	messageNew := map[imap.NotifyEvent]bool{imap.NotifyEventMessageNew: true, imap.NotifyEventMessageExpunge: true}
	flagChange := map[imap.NotifyEvent]bool{imap.NotifyEventFlagChange: true}
	treeOnly := map[imap.NotifyEvent]bool{imap.NotifyEventMailboxName: true}

	if opts := notifyStatusOptions(treeOnly, false); opts != nil {
		t.Errorf("tree-only events must not produce STATUS, got %+v", opts)
	}
	if opts := notifyStatusOptions(nil, true); opts != nil {
		t.Errorf("no events must not produce STATUS, got %+v", opts)
	}

	opts := notifyStatusOptions(messageNew, false)
	if opts == nil || !opts.NumMessages || !opts.UIDNext || !opts.UIDValidity {
		t.Errorf("MessageNew/MessageExpunge STATUS items wrong: %+v", opts)
	}
	if opts.HighestModSeq {
		t.Errorf("HIGHESTMODSEQ must not be sent to a non-CONDSTORE client: %+v", opts)
	}

	opts = notifyStatusOptions(messageNew, true)
	if opts == nil || !opts.HighestModSeq {
		t.Errorf("HIGHESTMODSEQ expected for CONDSTORE-aware clients: %+v", opts)
	}

	opts = notifyStatusOptions(flagChange, false)
	if opts == nil || !opts.UIDValidity || !opts.NumUnseen || opts.HighestModSeq {
		t.Errorf("FlagChange STATUS items without CONDSTORE wrong: %+v", opts)
	}
	opts = notifyStatusOptions(flagChange, true)
	if opts == nil || !opts.UIDValidity || !opts.HighestModSeq {
		t.Errorf("FlagChange STATUS items with CONDSTORE wrong: %+v", opts)
	}
}

func TestMailboxNameHasPrefix(t *testing.T) {
	tests := []struct {
		name, root string
		want       bool
	}{
		{"Lists/Lemonade", "Lists", true},
		{"lists/lemonade", "Lists", true},
		{"Lists", "Lists", false},        // the root itself is not "under" the root
		{"ListsArchive", "Lists", false}, // sibling sharing a name prefix
		{"Li", "Lists", false},
		{"Lists/", "Lists", false}, // no child name after the delimiter
	}
	for _, tc := range tests {
		if got := mailboxNameHasPrefix(tc.name, tc.root); got != tc.want {
			t.Errorf("mailboxNameHasPrefix(%q, %q) = %v, want %v", tc.name, tc.root, got, tc.want)
		}
	}
}
