package imap

import (
	"sort"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/pkg/metrics"
)

func (s *IMAPSession) Expunge(w *imapserver.ExpungeWriter, uidSet *imap.UIDSet) error {
	// First phase: Read session state with simple read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.DebugLog("failed to acquire read lock")
		return s.internalError("failed to acquire lock for expunge")
	}
	if s.selectedMailbox == nil {
		release()
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "No mailbox selected",
		}
	}
	mailboxID := s.selectedMailbox.ID
	AccountID := s.AccountID()
	// RFC 5182: resolve a "$" marker (UID EXPUNGE $) to the saved search result.
	if uidSet != nil && imap.IsSearchRes(*uidSet) {
		resolved := s.savedSearchResultLocked()
		uidSet = &resolved
	}
	release()

	// Check ACL permissions - requires 'e' (expunge) right
	hasExpungeRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, mailboxID, AccountID, 'e')
	if err != nil {
		return s.internalError("failed to check expunge permission: %v", err)
	}
	if !hasExpungeRight {
		s.DebugLog("user does not have expunge permission")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to expunge messages from this mailbox",
		}
	}

	// Middle phase: Get messages to expunge (outside lock)
	// Use optimized function that only fetches UIDs and sequence numbers
	deletedMessages, err := s.server.rdb.GetDeletedMessageUIDsAndSeqsWithRetry(s.ctx, mailboxID)
	if err != nil {
		return s.internalError("failed to fetch deleted messages: %v", err)
	}

	var messagesToExpunge []struct {
		uid imap.UID
		seq uint32
	}

	if uidSet != nil {
		for _, msg := range deletedMessages {
			if uidSet.Contains(msg.UID) {
				messagesToExpunge = append(messagesToExpunge, struct {
					uid imap.UID
					seq uint32
				}{uid: msg.UID, seq: msg.Seq})
			}
		}
	} else {
		for _, msg := range deletedMessages {
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
	_, err = s.server.rdb.ExpungeMessageUIDsWithRetry(s.ctx, mailboxID, uidsToDelete...)
	if err != nil {
		return s.internalError("failed to expunge messages: %v", err)
	}

	// Final phase: Update session state with simple write lock
	acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.DebugLog("failed to acquire write lock")
		return s.internalError("failed to acquire lock for expunge")
	}

	// Verify mailbox still selected and tracker still valid
	if s.selectedMailbox == nil || s.selectedMailbox.ID != mailboxID || s.mailboxTracker == nil {
		release()
		return nil
	}

	// Atomically subtract the number of expunged messages from the total count.
	s.currentNumMessages.Add(^uint32(len(messagesToExpunge) - 1))

	// NOTE: We intentionally do NOT advance currentHighestModSeq here.
	// If we set it to newModSeq, we jump the poll cursor forward and skip any
	// events from OTHER sessions that happened between the old modseq and newModSeq
	// (e.g., deliveries, flag changes, or expunges by other sessions).
	// Instead, we let Poll naturally discover ALL events. When Poll encounters
	// this session's own expunge events, QueueExpunge will harmlessly panic
	// (already processed), be recovered, and counted as skippedExpunges.

	// Sort messages to expunge by sequence number in descending order.
	// This ensures that when expunging multiple messages, we start with the
	// highest sequence number and work downward, avoiding problems with shifting sequence numbers.
	sort.Slice(messagesToExpunge, func(i, j int) bool {
		return messagesToExpunge[i].seq > messagesToExpunge[j].seq
	})

	// Update the tracker inside the write lock so that currentNumMessages and the
	// tracker's internal count stay in sync. If we released the lock first, a concurrent
	// Poll could see currentNumMessages already decremented but the tracker still at the
	// old count, causing a desync and unnecessary BYE disconnection.
	for _, m := range messagesToExpunge {
		if m.seq > 0 && s.mailboxTracker != nil {
			func() {
				defer func() {
					if r := recover(); r != nil {
						s.WarnLog("tracker panic during expunge", "seq", m.seq, "error", r)
					}
				}()
				s.mailboxTracker.QueueExpunge(m.seq)
			}()
		}
	}

	release()

	// Send expunge notifications to the client (network I/O, outside the lock).
	for _, m := range messagesToExpunge {
		if m.seq > 0 {
			if err := w.WriteExpunge(m.seq); err != nil {
				s.DebugLog("error writing expunge", "seq", m.seq, "uid", m.uid, "error", err)
				return s.internalError("failed to write expunge notification: %v", err)
			}
		}
	}

	s.DebugLog("expunge command processed", "count", len(messagesToExpunge))

	// Track domain and user command activity - EXPUNGE is database intensive!
	if s.IMAPUser != nil && len(messagesToExpunge) > 0 {
		metrics.TrackDomainCommand("imap", s.IMAPUser.Address.Domain(), "EXPUNGE")
		metrics.TrackUserActivity("imap", s.IMAPUser.Address.FullAddress(), "command", 1)
		metrics.TrackDomainMessage("imap", s.IMAPUser.Address.Domain(), "deleted")
	}

	// Track for session summary
	s.messagesExpunged.Add(uint32(len(messagesToExpunge)))

	return nil
}
