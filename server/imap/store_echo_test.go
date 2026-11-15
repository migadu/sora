package imap

import (
	"maps"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	serverPkg "github.com/migadu/sora/server"
)

func TestStoreOwnEchoRecordingAndModSeqCheck(t *testing.T) {
	t.Run("records when tracker empty and no fetch in flight", func(t *testing.T) {
		s := &IMAPSession{}
		s.currentHighestModSeq.Store(10)
		tracker := imapserver.NewMailboxTracker(3).NewSession()

		if !s.clientHasModSeqLocked(tracker, 7, 1, 10) {
			t.Fatal("clientHasModSeqLocked = false at cursor with empty tracker, want true")
		}
		s.recordOwnStoreEchoLocked(tracker, 7, 1, 11)
		if want := map[imap.UID]uint64{1: 11}; !maps.Equal(s.ownStoreEcho, want) || s.ownStoreEchoMailboxID != 7 {
			t.Fatalf("ownStoreEcho = %v in mailbox %d, want %v in mailbox 7", s.ownStoreEcho, s.ownStoreEchoMailboxID, want)
		}
		if !s.clientHasModSeqLocked(tracker, 7, 1, 11) {
			t.Fatal("clientHasModSeqLocked = false for own echoed modSeq, want true")
		}
	})

	t.Run("skips when tracker holds queued updates", func(t *testing.T) {
		s := &IMAPSession{}
		s.currentHighestModSeq.Store(10)
		mailbox := imapserver.NewMailboxTracker(3)
		tracker := mailbox.NewSession()
		_ = mailbox.QueueExpunge(3, 3)
		_ = mailbox.QueueMessageFlags(1, 1, []imap.Flag{imap.FlagAnswered}, 10, nil)

		if s.clientHasModSeqLocked(tracker, 7, 1, 10) {
			t.Fatal("clientHasModSeqLocked = true while update at cursor is still queued in tracker")
		}
		s.recordOwnStoreEchoLocked(tracker, 7, 1, 11)
		if s.ownStoreEcho != nil {
			t.Fatalf("recorded %v while tracker held queued updates", s.ownStoreEcho)
		}
	})

	t.Run("skips while FETCH is in flight", func(t *testing.T) {
		s := &IMAPSession{}
		endFetch := s.beginFetch()
		defer endFetch()

		tracker := imapserver.NewMailboxTracker(3).NewSession()
		s.recordOwnStoreEchoLocked(tracker, 7, 1, 11)
		if s.ownStoreEcho != nil {
			t.Fatalf("recorded %v while FETCH was in flight", s.ownStoreEcho)
		}
	})

	t.Run("bounded by maxFetchSeenEchoEntries", func(t *testing.T) {
		s := &IMAPSession{ownStoreEcho: make(map[imap.UID]uint64), ownStoreEchoMailboxID: 7}
		for i := range maxFetchSeenEchoEntries {
			s.ownStoreEcho[imap.UID(i+10)] = 1
		}
		tracker := imapserver.NewMailboxTracker(3).NewSession()

		// New UID past cap is not added.
		s.recordOwnStoreEchoLocked(tracker, 7, 1, 21)
		if len(s.ownStoreEcho) != maxFetchSeenEchoEntries {
			t.Fatalf("len(ownStoreEcho) = %d, want %d", len(s.ownStoreEcho), maxFetchSeenEchoEntries)
		}
		if _, exists := s.ownStoreEcho[1]; exists {
			t.Fatal("extended full ownStoreEcho with new UID")
		}

		// Existing UID updates in place without growing the map.
		s.recordOwnStoreEchoLocked(tracker, 7, 10, 22)
		if s.ownStoreEcho[10] != 22 {
			t.Fatalf("ownStoreEcho[10] = %d, want 22", s.ownStoreEcho[10])
		}
	})

	t.Run("bounded by session memory tracker", func(t *testing.T) {
		s := &IMAPSession{memTracker: serverPkg.NewSessionMemoryTracker(256)}
		tracker := imapserver.NewMailboxTracker(3).NewSession()
		s.recordOwnStoreEchoLocked(tracker, 7, 1, 21)
		if s.ownStoreEcho != nil || s.memTracker.Current() != 0 {
			t.Fatal("recorded optional echo metadata without spare memory headroom")
		}
	})
}
