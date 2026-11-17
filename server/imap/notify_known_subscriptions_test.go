package imap

import (
	"testing"

	"github.com/migadu/sora/db"
)

func TestNotifyRenameUsesKnownSubscriptionNames(t *testing.T) {
	for _, preexisting := range []bool{false, true} {
		watch := &notifyWatch{snapshot: testSnapshotKeys(map[int64]notifySnapshotEntry{1: {name: "Shared/Old"}}), knownSubscriptions: map[string]bool{}}
		if preexisting {
			watch.knownSubscriptions["shared/new"] = true
		}
		watch.ownRenamed([]db.MailboxNameMutation{{ID: 1, BeforeName: "Shared/Old", BeforeKey: "shared/old", AfterName: "Shared/New", AfterKey: "shared/new", SubscribedSet: true}})
		cur := testSnapshotKeys(map[int64]notifySnapshotEntry{1: {name: "Shared/New", subscribed: true}})
		got := diffNotifySnapshots(watch.snapshot, cur)
		if (len(got) == 0) != preexisting {
			t.Fatalf("preexisting=%v events=%v: only an unobserved subscription is foreign", preexisting, got)
		}
	}
}

func TestNotifyOwnerRenameMovesKnownGhostDescendants(t *testing.T) {
	watch := &notifyWatch{
		snapshot:           testSnapshotKeys(map[int64]notifySnapshotEntry{1: {name: "Old"}}),
		knownSubscriptions: map[string]bool{"old/ghost": true, "new/existing": true, "older/other": true},
	}
	watch.ownRenamed([]db.MailboxNameMutation{{ID: 1, BeforeName: "Old", BeforeKey: "old", AfterName: "New", AfterKey: "new"}})
	if watch.knownSubscriptions["old/ghost"] || !watch.knownSubscriptions["new/ghost"] || watch.knownSubscriptions["new/existing"] || !watch.knownSubscriptions["older/other"] {
		t.Fatalf("owner rename failed to retain known name-based subscriptions: %v", watch.knownSubscriptions)
	}
	// Materializing the formerly missing child in this client's own transaction
	// must not make its old, already-known subscription look foreign.
	watch.ownCreated(db.CreatedMailbox{NotifyMailbox: db.NotifyMailbox{ID: 2, Name: "Shared/From", NameKey: "shared/from"}, Visible: true})
	watch.ownRenamed([]db.MailboxNameMutation{{ID: 2, BeforeName: "Shared/From", BeforeKey: "shared/from", AfterName: "New/ghost", AfterKey: "new/ghost", SubscribedSet: true}})
	if !watch.snapshot[2].subscribed {
		t.Fatal("known ghost descendant subscription was lost")
	}
}

func TestNotifyOwnGhostSubscriptionIsRecordedOnlyWhenChanged(t *testing.T) {
	watch := &notifyWatch{knownSubscriptions: make(map[string]bool)}
	watch.ownSubscribed(db.SubscriptionMutation{NameKey: "shared/new", Subscribed: true, Changed: true})
	if !watch.knownSubscriptions["shared/new"] {
		t.Fatal("own SUBSCRIBE without a mailbox was not recorded")
	}
	watch.ownSubscribed(db.SubscriptionMutation{NameKey: "shared/new", Subscribed: false, Changed: true})
	if watch.knownSubscriptions["shared/new"] {
		t.Fatal("own UNSUBSCRIBE without a mailbox was not recorded")
	}
	watch.ownSubscribed(db.SubscriptionMutation{NameKey: "shared/new", Subscribed: true, Changed: false})
	if watch.knownSubscriptions["shared/new"] {
		t.Fatal("idempotent own SUBSCRIBE absorbed an unknown foreign change")
	}
}
