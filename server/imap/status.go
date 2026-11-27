package imap

import (
	"context"
	"fmt"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
)

// checkStatusItems refuses the STATUS data items this session does not offer,
// for STATUS and for LIST RETURN (STATUS), whose items are those of STATUS (RFC
// 5819 §2). It runs before anything is written: go-imap writes the STATUS line
// as it goes and cannot take back an item the session leaves unset.
func (s *IMAPSession) checkStatusItems(options *imap.StatusOptions) error {
	// IMAP4rev2 has no RECENT item (RFC 9051 Appendix E item 12; status-att in
	// §9). go-imap refuses it on STATUS for a session served IMAP4rev2 but not
	// on LIST RETURN (STATUS), so refuse it here, with STATUS's answer.
	if options.NumRecent && s.conn != nil && s.conn.IsIMAP4rev2() {
		return &imap.Error{
			Type: imap.StatusResponseTypeBad,
			Text: "Unknown STATUS data item",
		}
	}
	// RFC 8438 §1: with LIST-STATUS, SIZE "can be queried for many mailboxes at
	// once using just one LIST command", so it needs STATUS=SIZE there as well.
	if options.Size {
		if err := s.requireCapability(imap.CapStatusSize, "STATUS SIZE"); err != nil {
			return err
		}
	}
	// DELETED is IMAP4rev2's (RFC 9051 §6.3.11); RFC 3501 has no such item.
	// QUOTA=RES-MESSAGE would offer it too (RFC 9208 §4.1.4), but sora's QUOTA
	// reports STORAGE only.
	if options.NumDeleted {
		if err := s.requireCapability(imap.CapIMAP4rev2, "STATUS DELETED"); err != nil {
			return err
		}
	}
	// DELETED-STORAGE comes with QUOTA=RES-STORAGE (RFC 9208 §4.1.4, §5.1), which
	// sora advertises whenever it advertises QUOTA.
	if options.DeletedStorage {
		if err := s.requireCapability(imap.CapQuota, "STATUS DELETED-STORAGE"); err != nil {
			return err
		}
	}
	return nil
}

func (s *IMAPSession) Status(ctx context.Context, mboxName string, options *imap.StatusOptions) (*imap.StatusData, error) {
	if err := s.checkStatusItems(options); err != nil {
		return nil, err
	}
	// Prevent querying STATUS on the shared-namespace root, which is a
	// non-selectable container (matching SELECT/EXAMINE and LIST's \Noselect).
	if s.server.config != nil && s.server.config.SharedMailboxes.IsNamespaceRoot(mboxName) {
		s.DebugLog("cannot get status of shared namespace root", "mailbox", mboxName)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeCannot,
			Text: "The shared namespace root cannot be queried with STATUS",
		}
	}
	ctx = s.pinnedContext(ctx)

	// First phase: Read validation with read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		s.WarnLog("failed to acquire read lock")
		return nil, s.internalError("failed to acquire lock for status")
	}
	AccountID := s.AccountID()
	release()

	// Middle phase: Database operations outside lock
	mailbox, err := s.server.rdb.GetMailboxByNameWithRetry(ctx, AccountID, mboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.DebugLog("mailbox does not exist", "mailbox", mboxName)
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mboxName),
			}
		}
		return nil, s.internalError("failed to fetch mailbox '%s': %v", mboxName, err)
	}

	// Check ACL permissions - requires 'r' (read) right
	hasReadRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(ctx, mailbox.ID, AccountID, 'r')
	if err != nil {
		return nil, s.internalError("failed to check read permission: %v", err)
	}
	if !hasReadRight {
		s.DebugLog("user does not have read permission on mailbox", "mailbox", mboxName)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to get status of this mailbox",
		}
	}

	summary, err := s.server.rdb.GetMailboxSummaryWithRetry(ctx, mailbox.ID)
	if err != nil {
		return nil, s.internalError("failed to get mailbox summary for '%s': %v", mboxName, err)
	}

	statusData := &imap.StatusData{
		Mailbox:     mailbox.Name,
		UIDValidity: mailbox.UIDValidity,
	}

	if options.NumMessages {
		num := uint32(summary.NumMessages)

		// We DO NOT update s.currentNumMessages here even if this is the selected mailbox.
		// s.currentNumMessages must stay in sync with s.mailboxTracker's internal count.
		// Updating it here without updating the tracker causes desync panics later
		// during Poll or Append if the database count decreased (e.g., due to expunges).

		statusData.NumMessages = &num
	}
	if options.UIDNext {
		statusData.UIDNext = imap.UID(summary.UIDNext)
	}
	if options.NumRecent {
		num := s.statusNumRecent(ctx, mailbox.ID, summary)
		statusData.NumRecent = &num
	}
	if options.NumUnseen {
		// The unseen_count cache can underflow below zero under concurrent
		// flag/expunge races on the same mailbox (see db.lockMailboxStats). When we
		// observe a negative value, self-heal by recomputing it from the
		// authoritative message_state, then use the repaired value. Fall back to a
		// clamp to 0 if the repair fails, to prevent uint32 wraparound.
		unseenCount := summary.UnseenCount
		if unseenCount < 0 {
			s.WarnLog("negative unseen_count detected, recomputing", "mailbox", mboxName, "unseen_count", unseenCount)
			if repaired, rErr := s.server.rdb.RecomputeMailboxUnseenWithRetry(ctx, mailbox.ID); rErr != nil {
				s.WarnLog("failed to recompute unseen_count, clamping to 0", "mailbox", mboxName, "err", rErr)
				unseenCount = 0
			} else {
				unseenCount = int(repaired)
			}
		}
		num := uint32(unseenCount)
		statusData.NumUnseen = &num
	}
	if s.GetCapabilities().Has(imap.CapCondStore) && options.HighestModSeq {
		statusData.HighestModSeq = summary.HighestModSeq
	}
	if options.AppendLimit {
		limit := s.AppendLimit()
		statusData.AppendLimit = &limit
	}
	if options.NumDeleted || options.DeletedStorage {
		deleted, err := s.server.rdb.CountDeletedMessagesWithRetry(ctx, []int64{mailbox.ID})
		if err != nil {
			return nil, s.internalError("failed to count deleted messages in '%s': %v", mboxName, err)
		}
		setDeletedStatus(statusData, options, deleted[mailbox.ID])
	}
	if options.Size {
		// RFC 8438: SIZE is the sum of RFC822.SIZE of all messages in the
		// mailbox. Served from the mailbox_stats cache (total_size).
		size := summary.TotalSize
		statusData.Size = &size
	}

	numMessagesStr := "n/a"
	if statusData.NumMessages != nil {
		numMessagesStr = fmt.Sprint(*statusData.NumMessages)
	}

	s.DebugLog("mailbox status", "mailbox", mboxName, "num_messages", numMessagesStr, "uid_next", statusData.UIDNext, "highest_modseq", statusData.HighestModSeq)

	return statusData, nil
}
