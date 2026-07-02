package imap

import (
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
	// RFC 3501 §6.3.2: EXPUNGE mutates the mailbox and is not permitted on a
	// mailbox opened read-only with EXAMINE.
	if s.selectedReadOnly.Load() {
		release()
		s.DebugLog("expunge rejected: mailbox opened read-only (EXAMINE)")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCode("READ-ONLY"),
			Text: "Mailbox is read-only (opened with EXAMINE)",
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

	// Middle phase: Get the \Deleted messages to expunge (outside lock).
	// Only the UIDs are needed — sequence numbers for the EXPUNGE notifications
	// are computed by the post-command poll (see the notification note below).
	deletedMessages, err := s.server.rdb.GetDeletedMessageUIDsAndSeqsWithRetry(s.ctx, mailboxID)
	if err != nil {
		return s.internalError("failed to fetch deleted messages: %v", err)
	}

	var uidsToDelete []imap.UID
	for _, msg := range deletedMessages {
		// For UID EXPUNGE (RFC 4315), restrict to the requested UID set.
		if uidSet != nil && !uidSet.Contains(msg.UID) {
			continue
		}
		uidsToDelete = append(uidsToDelete, msg.UID)
	}

	if len(uidsToDelete) == 0 {
		return nil
	}

	// Database operation - no lock needed
	_, err = s.server.rdb.ExpungeMessageUIDsWithRetry(s.ctx, mailboxID, uidsToDelete...)
	if err != nil {
		return s.internalError("failed to expunge messages: %v", err)
	}

	// Notification is handled entirely by the post-command poll, exactly like
	// MOVE (see server/imap/move.go). go-imap calls conn.poll() before writing the
	// tagged OK, which runs Sora's DB poll; that poll detects these soft-expunges,
	// decrements currentNumMessages, queues the EXPUNGEs on the tracker (for this
	// session AND every other session watching the mailbox), and flushes them —
	// satisfying RFC 3501 §7.4.1 (EXPUNGE before tagged OK).
	//
	// We deliberately do NOT also emit notifications here. Previously this handler
	// wrote EXPUNGEs directly (w.WriteExpunge) AND broadcast them via QueueExpunge
	// (source=nil, which includes this very session). The post-command poll then
	// re-discovered the same expunges (the modseq cursor is intentionally not
	// advanced). The result was the issuing client receiving each EXPUNGE up to
	// three times plus a spurious EXISTS from the double-decremented count — which
	// made adjacent messages momentarily vanish (the duplicate EXPUNGE removed
	// whatever shifted into that sequence number) and left blank phantom rows
	// (the bogus EXISTS) until the client resynced. Relying solely on the poll, as
	// MOVE does, emits each EXPUNGE exactly once with no phantom EXISTS.

	s.DebugLog("expunge command processed", "count", len(uidsToDelete))

	// Track domain and user command activity - EXPUNGE is database intensive!
	if s.IMAPUser != nil && len(uidsToDelete) > 0 {
		metrics.TrackDomainCommand("imap", s.IMAPUser.Address.Domain(), "EXPUNGE")
		metrics.TrackUserActivity("imap", s.IMAPUser.Address.FullAddress(), "command", 1)
		metrics.TrackDomainMessage("imap", s.IMAPUser.Address.Domain(), "deleted")
	}

	// Track for session summary
	s.messagesExpunged.Add(uint32(len(uidsToDelete)))

	return nil
}
