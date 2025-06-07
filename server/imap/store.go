package imap

import (
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

func (s *IMAPSession) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.selectedMailbox == nil {
		s.Log("[STORE] store failed: no mailbox selected")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "no mailbox selected",
		}
	}

	numSet = s.decodeNumSet(numSet)

	messages, err := s.server.db.GetMessagesByNumSet(s.ctx, s.selectedMailbox.ID, numSet)
	if err != nil {
		return s.internalError("failed to retrieve messages: %v", err)
	}

	var modifiedMessages []struct {
		seq    uint32
		uid    imap.UID
		flags  []imap.Flag
		modSeq int64
	}

	for _, msg := range messages {
		// CONDSTORE: Skip messages whose mod-sequence is greater than the UNCHANGEDSINCE value
		_, hasCondStore := s.server.caps[imap.CapCondStore]
		if hasCondStore && options != nil && options.UnchangedSince > 0 {
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

	if !flags.Silent {
		for _, modified := range modifiedMessages {
			m := w.CreateMessage(s.sessionTracker.EncodeSeqNum(modified.seq))

			m.WriteFlags(modified.flags)
			m.WriteUID(modified.uid)
			// m.WriteModSeq(uint64(modified.modSeq))

			if err := m.Close(); err != nil {
				s.Log("[STORE] WARNING: failed to close fetch response for message UID %d: %v",
					modified.uid, err)
			}
		}
	}

	return nil
}
