package imap

import (
	"maps"
	"slices"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/db"
	serverPkg "github.com/migadu/sora/server"
)

func TestApplyImplicitSeenUpdate(t *testing.T) {
	oldModSeq := int64(10)
	msg := db.Message{UID: 1, BitwiseFlags: db.FlagFlagged, CreatedModSeq: 5, UpdatedModSeq: &oldModSeq}

	// No result for the message: the update changed nothing (it was \Seen already).
	for _, results := range [][]db.BatchFlagUpdateResult{
		nil,
		{{UID: 2, Flags: []imap.Flag{imap.FlagSeen}, ModSeq: 20}},
		{{UID: 1, ModSeq: 20, PreconditionFailed: true}},
	} {
		if applyImplicitSeenUpdate(&msg, results) {
			t.Fatalf("applyImplicitSeenUpdate(%v) = true, want false", results)
		}
		if *msg.UpdatedModSeq != 10 || msg.BitwiseFlags != db.FlagFlagged {
			t.Fatalf("applyImplicitSeenUpdate(%v) changed the message: flags %d, modseq %d", results, msg.BitwiseFlags, *msg.UpdatedModSeq)
		}
	}

	if !applyImplicitSeenUpdate(&msg, []db.BatchFlagUpdateResult{
		{UID: 1, Flags: []imap.Flag{imap.FlagSeen, imap.FlagFlagged, "$Work"}, ModSeq: 21},
	}) {
		t.Fatal("applyImplicitSeenUpdate = false, want true")
	}
	if msg.UpdatedModSeq == nil || *msg.UpdatedModSeq != 21 {
		t.Fatalf("UpdatedModSeq = %v, want 21", msg.UpdatedModSeq)
	}
	if !db.ContainsFlag(msg.BitwiseFlags, db.FlagSeen) || !db.ContainsFlag(msg.BitwiseFlags, db.FlagFlagged) {
		t.Fatalf("BitwiseFlags = %d, want Seen|Flagged", msg.BitwiseFlags)
	}
	if !slices.Equal(msg.CustomFlags, []string{"$Work"}) {
		t.Fatalf("CustomFlags = %v, want [$Work]", msg.CustomFlags)
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

	t.Run("another FETCH in flight", func(t *testing.T) {
		s := &IMAPSession{}
		first := s.beginFetch()
		second := s.beginFetch()
		a := s.lockImplicitSeenAnswer(7)
		a.expect(changed, imapserver.NewMailboxTracker(3).NewSession())
		if locked(s) {
			t.Fatal("ownStoreMu held while another FETCH can carry older flags")
		}
		a.answered(1, 21)
		a.release()
		if s.ownStoreEcho != nil {
			t.Fatalf("recorded %v during overlapping FETCH responses", s.ownStoreEcho)
		}
		second()
		first()
		if s.fetchInFlight != 0 {
			t.Fatalf("in-flight FETCH count = %d after completion", s.fetchInFlight)
		}
	})

	t.Run("bounded memo", func(t *testing.T) {
		s := &IMAPSession{ownStoreEcho: make(map[imap.UID]uint64), ownStoreEchoMailboxID: 7}
		for i := range maxFetchSeenEchoEntries {
			s.ownStoreEcho[imap.UID(i+10)] = 1
		}
		a := s.lockImplicitSeenAnswer(7)
		a.expect(changed, imapserver.NewMailboxTracker(3).NewSession())
		if locked(s) {
			t.Fatal("optional memo limit kept Poll locked")
		}
		a.answered(1, 21)
		a.release()
		if len(s.ownStoreEcho) != maxFetchSeenEchoEntries {
			t.Fatal("FETCH extended a full echo memo")
		}
	})

	t.Run("ordinary full batches", func(t *testing.T) {
		s := &IMAPSession{}
		for batch := range 2 {
			// Match db.defaultFetchChunkSize: ordinary full batches must still
			// be memoized rather than always taking the conservative fallback.
			changed := make(map[imap.UID]bool, 5000)
			for i := range 5000 {
				changed[imap.UID(batch*5000+i+1)] = true
			}
			a := s.lockImplicitSeenAnswer(7)
			a.expect(changed, imapserver.NewMailboxTracker(10000).NewSession())
			for uid := range changed {
				a.answered(uid, 21)
			}
			a.release()
		}
		if len(s.ownStoreEcho) != 10000 {
			t.Fatalf("ordinary batches retained %d answers, want 10000", len(s.ownStoreEcho))
		}
	})

	t.Run("no spare metadata headroom", func(t *testing.T) {
		s := &IMAPSession{memTracker: serverPkg.NewSessionMemoryTracker(256)}
		a := s.lockImplicitSeenAnswer(7)
		a.expect(changed, imapserver.NewMailboxTracker(3).NewSession())
		if locked(s) {
			t.Fatal("optional memo headroom kept Poll locked")
		}
		a.answered(1, 21)
		a.release()
		if s.ownStoreEcho != nil || s.memTracker.Current() != 0 {
			t.Fatal("FETCH retained optional state without spare headroom")
		}
	})
}
