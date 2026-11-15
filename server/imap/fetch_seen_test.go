package imap

import (
	"maps"
	"slices"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/db"
)

func TestApplyImplicitSeenUpdates(t *testing.T) {
	oldModSeq := int64(10)
	msgs := []db.Message{
		{UID: 1, BitwiseFlags: 0, CreatedModSeq: 5, UpdatedModSeq: &oldModSeq},
		{UID: 2, BitwiseFlags: db.FlagSeen, CreatedModSeq: 6},
		{UID: 3, BitwiseFlags: db.FlagFlagged, CreatedModSeq: 7},
	}

	unseen := unseenMessageUIDs(msgs)
	if !slices.Equal(unseen, []imap.UID{1, 3}) {
		t.Fatalf("unseenMessageUIDs = %v, want [1 3]", unseen)
	}

	changed := applyImplicitSeenUpdates(msgs, []db.BatchFlagUpdateResult{
		{UID: 1, Flags: []imap.Flag{imap.FlagSeen, "$Work"}, ModSeq: 21},
		{UID: 3, Flags: []imap.Flag{imap.FlagSeen, imap.FlagFlagged}, ModSeq: 22},
	})

	if !changed[1] || changed[2] || !changed[3] {
		t.Fatalf("changed = %v, want {1:true, 3:true}", changed)
	}
	if msgs[0].UpdatedModSeq == nil || *msgs[0].UpdatedModSeq != 21 {
		t.Fatalf("msg 1 UpdatedModSeq = %v, want 21", msgs[0].UpdatedModSeq)
	}
	if !db.ContainsFlag(msgs[0].BitwiseFlags, db.FlagSeen) || !slices.Equal(msgs[0].CustomFlags, []string{"$Work"}) {
		t.Fatalf("msg 1 flags = (%d, %v), want Seen + [$Work]", msgs[0].BitwiseFlags, msgs[0].CustomFlags)
	}
	if msgs[2].UpdatedModSeq == nil || *msgs[2].UpdatedModSeq != 22 {
		t.Fatalf("msg 3 UpdatedModSeq = %v, want 22", msgs[2].UpdatedModSeq)
	}
	if !db.ContainsFlag(msgs[2].BitwiseFlags, db.FlagSeen) || !db.ContainsFlag(msgs[2].BitwiseFlags, db.FlagFlagged) {
		t.Fatalf("msg 3 BitwiseFlags = %d, want Seen|Flagged", msgs[2].BitwiseFlags)
	}
}

// A FETCH batch holds ownStoreMu from its \Seen update until every changed
// message is answered, records only the answered ones, and records none while
// the session tracker holds updates an earlier poll queued.
func TestImplicitSeenAnswer(t *testing.T) {
	changed := map[imap.UID]bool{1: true, 3: true}
	locked := func(s *IMAPSession) bool {
		if s.ownStoreMu.TryLock() {
			s.ownStoreMu.Unlock()
			return false
		}
		return true
	}

	t.Run("answered", func(t *testing.T) {
		s := &IMAPSession{}
		tracker := imapserver.NewMailboxTracker(3).NewSession()
		a := s.lockImplicitSeenAnswer(7)
		a.expect(changed, tracker)
		a.answered(1, 21)
		if !locked(s) {
			t.Fatal("ownStoreMu released before every changed message was answered")
		}
		a.answered(3, 22)
		if locked(s) {
			t.Fatal("ownStoreMu still held after the last changed message was answered")
		}
		a.release()
		if want := map[imap.UID]uint64{1: 21, 3: 22}; !maps.Equal(s.ownStoreEcho, want) || s.ownStoreEchoMailboxID != 7 {
			t.Fatalf("ownStoreEcho = %v in mailbox %d, want %v in mailbox 7", s.ownStoreEcho, s.ownStoreEchoMailboxID, want)
		}
	})

	t.Run("unanswered", func(t *testing.T) {
		s := &IMAPSession{}
		a := s.lockImplicitSeenAnswer(7)
		a.expect(changed, imapserver.NewMailboxTracker(3).NewSession())
		a.answered(1, 21)
		a.release()
		if locked(s) {
			t.Fatal("ownStoreMu still held after the batch ended")
		}
		if want := map[imap.UID]uint64{1: 21}; !maps.Equal(s.ownStoreEcho, want) {
			t.Fatalf("ownStoreEcho = %v, want %v", s.ownStoreEcho, want)
		}
	})

	t.Run("held updates", func(t *testing.T) {
		s := &IMAPSession{}
		mailbox := imapserver.NewMailboxTracker(3)
		tracker := mailbox.NewSession()
		mailbox.QueueExpunge(2, 2)
		a := s.lockImplicitSeenAnswer(7)
		a.expect(changed, tracker)
		if locked(s) {
			t.Fatal("ownStoreMu held although nothing will be recorded")
		}
		a.answered(1, 21)
		a.answered(3, 22)
		a.release()
		if s.ownStoreEcho != nil {
			t.Fatalf("recorded %v while the tracker held an update", s.ownStoreEcho)
		}
	})

	t.Run("nothing changed", func(t *testing.T) {
		s := &IMAPSession{}
		a := s.lockImplicitSeenAnswer(7)
		a.expect(nil, imapserver.NewMailboxTracker(3).NewSession())
		if locked(s) {
			t.Fatal("ownStoreMu held although the update changed nothing")
		}
		a.release()
	})
}
