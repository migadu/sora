package imap

import (
	"sort"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/pkg/metrics"
)

func (s *IMAPSession) Expunge(w *imapserver.ExpungeWriter, uidSet *imap.UIDSet) error {
	// First phase: Read session state with simple read lock
	s.mutex.RLock()
	if s.selectedMailbox == nil {
		s.mutex.RUnlock()
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "No mailbox selected",
		}
	}
	mailboxID := s.selectedMailbox.ID
	sessionTrackerSnapshot := s.sessionTracker
	s.mutex.RUnlock()

	// Middle phase: Get messages to expunge (outside lock)
	messages, err := s.server.rdb.GetMessagesByFlagWithRetry(s.ctx, mailboxID, imap.FlagDeleted)
	if err != nil {
		return s.internalError("failed to fetch deleted messages: %v", err)
	}

	var messagesToExpunge []struct {
		uid imap.UID
		seq uint32
	}

	if uidSet != nil {
		for _, msg := range messages {
			if uidSet.Contains(msg.UID) {
				messagesToExpunge = append(messagesToExpunge, struct {
					uid imap.UID
					seq uint32
				}{uid: msg.UID, seq: msg.Seq})
			}
		}
	} else {
		for _, msg := range messages {
			messagesToExpunge = append(messagesToExpunge, struct {
				uid imap.UID
				seq uint32
			}{uid: msg.UID, seq: msg.Seq})
		}
	}

	if len(messagesToExpunge) == 0 {
		return nil
	}

	var uidsToDelete []imap.UID
	for _, m := range messagesToExpunge {
		uidsToDelete = append(uidsToDelete, m.uid)
	}

	// Database operation - no lock needed
	newModSeq, err := s.server.rdb.ExpungeMessageUIDsWithRetry(s.ctx, mailboxID, uidsToDelete...)
	if err != nil {
		return s.internalError("failed to expunge messages: %v", err)
	}

	// Final phase: Update session state with simple write lock
	s.mutex.Lock()

	// Verify mailbox still selected and tracker still valid
	if s.selectedMailbox == nil || s.selectedMailbox.ID != mailboxID || s.mailboxTracker == nil {
		s.mutex.Unlock()
		return nil
	}

	// Atomically subtract the number of expunged messages from the total count.
	s.currentNumMessages.Add(^uint32(len(messagesToExpunge) - 1))

	// Update highest MODSEQ to prevent POLL from re-processing these expunges
	if newModSeq > 0 {
		s.currentHighestModSeq.Store(uint64(newModSeq))
	}

	s.mutex.Unlock()

	// Sort messages to expunge by sequence number in descending order
	// This ensures that when expunging multiple messages, we start with the
	// highest sequence number and work downward, avoiding problems with shifting sequence numbers
	sort.Slice(messagesToExpunge, func(i, j int) bool {
		return messagesToExpunge[i].seq > messagesToExpunge[j].seq
	})

	// Send notifications using snapshot
	for _, m := range messagesToExpunge {
		if sessionTrackerSnapshot != nil {
			sessionSeqNum := sessionTrackerSnapshot.EncodeSeqNum(m.seq)
			if sessionSeqNum > 0 {
				if err := w.WriteExpunge(sessionSeqNum); err != nil {
					s.Log("[EXPUNGE] Error writing expunge for sessionSeqNum %d (UID %d, dbSeq %d): %v", sessionSeqNum, m.uid, m.seq, err)
					return s.internalError("failed to write expunge notification: %v", err)
				}
			}
		}
	}

	s.Log("[EXPUNGE] command processed, %d messages expunged from DB. Client notified.", len(messagesToExpunge))

	// Track domain and user command activity - EXPUNGE is database intensive!
	if s.IMAPUser != nil && len(messagesToExpunge) > 0 {
		metrics.TrackDomainCommand("imap", s.IMAPUser.Address.Domain(), "EXPUNGE")
		metrics.TrackUserActivity("imap", s.IMAPUser.Address.FullAddress(), "command", 1)
		metrics.TrackDomainMessage("imap", s.IMAPUser.Address.Domain(), "deleted")
	}

	return nil
}
