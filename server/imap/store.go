package imap

import (
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

func (s *IMAPSession) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	// First, safely read session state with a single mutex acquisition
	var selectedMailboxID int64
	var decodedNumSet imap.NumSet

	// Acquire read mutex to safely read session state
	s.mutex.RLock()
	if s.selectedMailbox == nil {
		s.mutex.RUnlock()
		s.Log("[STORE] store failed: no mailbox selected")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "no mailbox selected",
		}
	}

	selectedMailboxID = s.selectedMailbox.ID

	// Use our helper method that assumes the mutex is held (read lock is sufficient)
	decodedNumSet = s.decodeNumSetLocked(numSet)
	s.mutex.RUnlock()

	// Perform database operations outside of lock
	messages, err := s.server.db.GetMessagesByNumSet(s.ctx, selectedMailboxID, decodedNumSet)
	if err != nil {
		return s.internalError("failed to retrieve messages: %v", err)
	}

	var modifiedMessages []struct {
		seq    uint32
		uid    imap.UID
		flags  []imap.Flag
		modSeq int64
	}

	// Check if the context is still valid before proceeding with flag updates
	if s.ctx.Err() != nil {
		s.Log("[STORE] context cancelled before flag updates, aborting operation")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Session closed during store operation",
		}
	}

	for _, msg := range messages {
		// Always enable CONDSTORE functionality when UnchangedSince option is provided
		if options != nil && options.UnchangedSince > 0 {
			var currentModSeq int64
			currentModSeq = msg.CreatedModSeq

			if msg.UpdatedModSeq != nil && *msg.UpdatedModSeq > currentModSeq {
				currentModSeq = *msg.UpdatedModSeq
			}

			if msg.ExpungedModSeq != nil && *msg.ExpungedModSeq > currentModSeq {
				currentModSeq = *msg.ExpungedModSeq
			}

			if uint64(currentModSeq) > options.UnchangedSince {
				s.Log("[STORE] CONDSTORE: Skipping message UID %d with MODSEQ %d > UNCHANGEDSINCE %d",
					msg.UID, currentModSeq, options.UnchangedSince)
				continue
			}
		}

		var newFlags []imap.Flag
		var newModSeq int64
		switch flags.Op {
		case imap.StoreFlagsAdd:
			newFlags, newModSeq, err = s.server.db.AddMessageFlags(s.ctx, msg.UID, msg.MailboxID, flags.Flags)
		case imap.StoreFlagsDel:
			newFlags, newModSeq, err = s.server.db.RemoveMessageFlags(s.ctx, msg.UID, msg.MailboxID, flags.Flags)
		case imap.StoreFlagsSet:
			newFlags, newModSeq, err = s.server.db.SetMessageFlags(s.ctx, msg.UID, msg.MailboxID, flags.Flags)
		}

		if err != nil {
			return s.internalError("failed to update flags for message: %v", err)
		}

		if newModSeq == 0 { // Should not happen if DB functions are correct
			s.Log("[STORE] WARNING: message UID %d received zero MODSEQ after flag update", msg.UID)
		}

		s.Log("[STORE] operation updated message UID %d, new MODSEQ: %d", msg.UID, newModSeq)

		modifiedMessages = append(modifiedMessages, struct {
			seq    uint32
			uid    imap.UID
			flags  []imap.Flag
			modSeq int64
		}{
			seq:    msg.Seq,
			uid:    msg.UID,
			flags:  newFlags,
			modSeq: newModSeq,
		})
	}

	// Before responding with fetches, check if context is still valid
	if s.ctx.Err() != nil {
		s.Log("[STORE] context cancelled after flag updates, response will be incomplete")
		return nil
	}

	// Re-acquire read mutex to access session tracker for encoding sequence numbers in the response
	s.mutex.RLock()
	currentSessionTracker := s.sessionTracker // Get the current session tracker
	s.mutex.RUnlock()

	if !flags.Silent && currentSessionTracker != nil {
		for _, modified := range modifiedMessages {
			m := w.CreateMessage(currentSessionTracker.EncodeSeqNum(modified.seq))

			m.WriteFlags(modified.flags)
			m.WriteUID(modified.uid)
			// CONDSTORE: Uncomment the following line if CONDSTORE capability is used
			// m.WriteModSeq(uint64(modified.modSeq))

			if err := m.Close(); err != nil {
				s.Log("[STORE] WARNING: failed to close fetch response for message UID %d: %v",
					modified.uid, err)
			}
		}
	}

	return nil
}
