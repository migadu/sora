package imap

import (
	"context"
	"fmt"
	"strings"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/metrics"
)

func (s *IMAPSession) Select(ctx context.Context, mboxName string, options *imap.SelectOptions) (*imap.SelectData, error) {
	s.DebugLog("attempting to select mailbox", "mailbox", mboxName)

	if ctx.Err() != nil {
		s.DebugLog("request aborted before selecting mailbox", "mailbox", mboxName)
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Session closed"}
	}

	// Prevent selecting the shared namespace root
	// The namespace root (e.g., "Shared") should only be a container, not a selectable mailbox
	if s.server.config != nil && s.server.config.SharedMailboxes.Enabled {
		sharedPrefix := strings.TrimSuffix(s.server.config.SharedMailboxes.NamespacePrefix, "/")
		if strings.EqualFold(mboxName, sharedPrefix) {
			s.DebugLog("cannot select shared namespace root", "mailbox", mboxName)
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeCannot,
				Text: "The shared namespace root cannot be selected. Select mailboxes under it instead",
			}
		}
	}

	// Phase 1: Read session state with read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		s.WarnLog("failed to acquire read lock within timeout")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}
	AccountID := s.AccountID()
	release()

	// Create a context that signals to use the master DB if the session is pinned.
	readCtx := ctx
	if s.useMasterDB.Load() {
		readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	}

	// Phase 2: Database operations outside lock
	mailbox, err := s.server.rdb.GetMailboxByNameWithRetry(readCtx, AccountID, mboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.DebugLog("mailbox does not exist", "mailbox", mboxName)
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mboxName),
			}
		}

		return nil, s.internalError("failed to fetch mailbox '%s' for user %d: %v", mboxName, s.AccountID(), err)
	}

	// Check ACL permissions for shared mailboxes (requires 'r' read right)
	// The has_mailbox_right function returns TRUE for owners, so this works for both personal and shared mailboxes
	hasReadRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(readCtx, mailbox.ID, AccountID, 'r')
	if err != nil {
		return nil, s.internalError("failed to check read permission for mailbox '%s': %v", mboxName, err)
	}
	if !hasReadRight {
		s.DebugLog("user does not have read permission on mailbox", "mailbox", mboxName)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to select this mailbox",
		}
	}

	// Compute the user's effective rights once, for READ-ONLY signalling (RFC 4314
	// §5.2) and PERMANENTFLAGS filtering (§5.1.1).
	userRights, err := s.userRightsForMailbox(readCtx, mailbox.ID, mailbox.AccountID)
	if err != nil {
		return nil, s.internalError("failed to get user rights for mailbox '%s': %v", mboxName, err)
	}

	// EXAMINE and ACL-forced read-only SELECT must use the same state rules.
	examined := options != nil && options.ReadOnly
	isReadOnly := examined || !strings.ContainsAny(userRights, "iestw")

	// Read the mailbox summary, first-unseen sequence number, defined flags, and QRESYNC
	// VANISHED/FETCH state inside one REPEATABLE READ READ ONLY transaction so every part
	// of the SELECT response describes the exact MVCC snapshot whose EXISTS, UIDNEXT, and
	// HIGHESTMODSEQ come from GetMailboxSummary. Changes committed by other sessions after
	// that snapshot (including in-place message_state overwrites and expunges of newly
	// delivered messages) remain invisible here and are reported by the session's next poll
	// from HighestModSeq.
	var (
		currentSummary    *db.MailboxSummary
		firstUnseenSeqNum uint32
		displayFlags      []imap.Flag
		vanishedUIDs      []imap.UID
		changedMsgs       []db.QResyncModifiedMessage
	)
	if err := s.server.rdb.InReadSnapshotWithRetry(readCtx, func(snapCtx context.Context) error {
		currentSummary = nil
		firstUnseenSeqNum = 0
		displayFlags = nil
		vanishedUIDs = nil
		changedMsgs = nil

		summary, err := s.server.rdb.GetMailboxSummaryWithRetry(snapCtx, mailbox.ID)
		if err != nil {
			return err
		}
		currentSummary = summary

		// Extract the first unseen message sequence number lazily for SELECT only.
		// We do not compute this in GetMailboxSummary to avoid O(N) counts in background STATUS checks.
		if summary.UnseenCount > 0 {
			nonFatalErr, fatalErr := s.server.rdb.OptionalReadInSnapshot(snapCtx, func(spCtx context.Context) error {
				seq, seqErr := s.server.rdb.GetFirstUnseenSeqNumWithRetry(spCtx, mailbox.ID)
				if seqErr != nil {
					return seqErr
				}
				firstUnseenSeqNum = seq
				return nil
			})
			if fatalErr != nil {
				return fatalErr
			}
			if nonFatalErr != nil {
				s.WarnLog("failed to dynamically compute first unseen sequence number", "mailbox_id", mailbox.ID, "err", nonFatalErr)
			}
		}

		flags, fatalErr := getDisplayFlagsInSnapshot(snapCtx, s.server.rdb, mailbox, s.DebugLog)
		if fatalErr != nil {
			return fatalErr
		}
		displayFlags = flags

		if options != nil && options.QResync != nil && options.QResync.UIDValidity == mailbox.UIDValidity {
			qr := options.QResync
			if len(qr.KnownUIDs) > 0 {
				var activeUIDs []imap.UID
				nonFatalErr, fatalErr := s.server.rdb.OptionalReadInSnapshot(snapCtx, func(spCtx context.Context) error {
					var activeErr error
					activeUIDs, activeErr = s.server.rdb.GetActiveUIDsInSetWithRetry(spCtx, mailbox.ID, qr.KnownUIDs)
					return activeErr
				})
				if fatalErr != nil {
					return fatalErr
				}
				if nonFatalErr != nil {
					s.WarnLog("failed to get active UIDs for QRESYNC", "err", nonFatalErr)
					fbErr, fbFatalErr := s.server.rdb.OptionalReadInSnapshot(snapCtx, func(spCtx context.Context) error {
						var vErr error
						vanishedUIDs, vErr = s.server.rdb.GetVanishedUIDsWithRetry(spCtx, mailbox.ID, qr.ModSeq, summary.HighestModSeq)
						return vErr
					})
					if fbFatalErr != nil {
						return fbFatalErr
					}
					if fbErr != nil {
						s.WarnLog("failed to get vanished UIDs fallback for QRESYNC", "err", fbErr)
					}
				} else {
					activeMap := make(map[imap.UID]struct{}, len(activeUIDs))
					for _, uid := range activeUIDs {
						activeMap[uid] = struct{}{}
					}

					uidNext := imap.UID(summary.UIDNext)
					for _, r := range qr.KnownUIDs {
						start := r.Start
						stop := r.Stop
						if uidNext > 0 && stop >= uidNext {
							stop = uidNext - 1
						}
						for uid := start; uid <= stop; uid++ {
							if _, ok := activeMap[uid]; !ok {
								vanishedUIDs = append(vanishedUIDs, uid)
							}
						}
					}
				}
			} else {
				nonFatalErr, fatalErr := s.server.rdb.OptionalReadInSnapshot(snapCtx, func(spCtx context.Context) error {
					var vErr error
					vanishedUIDs, vErr = s.server.rdb.GetVanishedUIDsWithRetry(spCtx, mailbox.ID, qr.ModSeq, summary.HighestModSeq)
					return vErr
				})
				if fatalErr != nil {
					return fatalErr
				}
				if nonFatalErr != nil {
					s.WarnLog("failed to get vanished UIDs for QRESYNC", "err", nonFatalErr)
				}
			}

			nonFatalErr, fatalErr := s.server.rdb.OptionalReadInSnapshot(snapCtx, func(spCtx context.Context) error {
				var cErr error
				changedMsgs, cErr = s.server.rdb.GetMessagesChangedSinceWithRetry(spCtx, mailbox.ID, qr.ModSeq)
				return cErr
			})
			if fatalErr != nil {
				return fatalErr
			}
			if nonFatalErr != nil {
				s.WarnLog("failed to get changed messages for QRESYNC", "err", nonFatalErr)
			}
		}

		return nil
	}); err != nil {
		return nil, s.internalError("failed to get current summary for selected mailbox '%s': %v", mboxName, err)
	}

	// First, acquire the read lock once to read necessary session state
	acquired, release = s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		s.WarnLog("failed to acquire second read lock within timeout")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}

	// Check if this is a reselection of the previously selected mailbox
	isReselectOfPrevious := (s.lastSelectedMailboxID == mailbox.ID)
	// Store the highest UID from previous selection to calculate recent messages
	uidToCompareAgainst := s.lastHighestUID
	// Check if the context is already cancelled before proceeding with DB operations
	if ctx.Err() != nil {
		release()
		s.DebugLog("context already cancelled before selecting mailbox", "mailbox", mboxName)
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Session closed during select operation"}
	}
	release()

	// Now perform all database operations outside the lock
	var numRecent uint32
	var recentAbove imap.UID // numRecent counts the messages above this UID

	if isReselectOfPrevious {
		s.DebugLog("mailbox reselected", "mailbox", mboxName)
		// A read-only open did not advance our last read-write baseline. Another
		// session may since have consumed newer Recent while this mailbox was
		// closed here, so an older local baseline must not revive those messages.
		if lastSeenUID, ok := s.server.mailboxRecentUIDs.Load(mailbox.ID); ok {
			uidToCompareAgainst = max(uidToCompareAgainst, lastSeenUID)
		}
		// This mailbox was the one most recently selected (and then unselected by the imapserver library).
		// Count messages with UID > uidToCompareAgainst. Use the potentially master-pinned context.
		count, dbErr := s.server.rdb.CountMessagesGreaterThanUIDWithRetry(readCtx, mailbox.ID, uidToCompareAgainst)
		if dbErr != nil {
			s.DebugLog("error counting messages greater than UID, defaulting RECENT to total", "uid", uidToCompareAgainst, "mailbox_id", mailbox.ID, "error", dbErr)
			numRecent = uint32(currentSummary.NumMessages) // Fallback
		} else {
			numRecent = count
			recentAbove = uidToCompareAgainst
		}
	} else {
		// Different mailbox or first select in this session.
		// RFC 3501 §2.3.2: \Recent messages are those that arrived since the last
		// time any read-write session selected this mailbox.
		//
		// We use a server-wide map (mailboxRecentUIDs) that records the highest UID
		// at the time of the last read-write SELECT by ANY session on this server.
		// This is an improvement over the previous per-session-only approach (which
		// reported ALL messages as recent for any new session) and is correct for
		// single-node deployments.  The state is in-memory and resets on restart;
		// true cross-node \Recent tracking would require a persistent store.
		if lastSeenUID, ok := s.server.mailboxRecentUIDs.Load(mailbox.ID); ok {
			count, dbErr := s.server.rdb.CountMessagesGreaterThanUIDWithRetry(readCtx, mailbox.ID, lastSeenUID)
			if dbErr != nil {
				s.DebugLog("error counting recent messages from server-wide UID, defaulting to total", "uid", lastSeenUID, "mailbox_id", mailbox.ID, "error", dbErr)
				numRecent = uint32(currentSummary.NumMessages)
			} else {
				numRecent = count
				recentAbove = lastSeenUID
			}
		} else {
			// No previous read-write SELECT on any session for this mailbox (since
			// server start).  All messages are considered recent.
			numRecent = uint32(currentSummary.NumMessages)
		}
	}

	// Acquire the lock once after all DB operations to update session state
	acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout(ctx)
	if !acquired {
		s.WarnLog("failed to acquire write lock within timeout")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}
	defer release()

	// Check again if the context was cancelled during DB operations
	if ctx.Err() != nil {
		s.DebugLog("request aborted during mailbox selection, aborting state update", "mailbox", mboxName)
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Session closed during select operation"}
	}

	// SEARCH RECENT, NEW and OLD answer from this (see recent.go).
	s.recentAboveUID = recentAbove

	// Only a read-write selection advances the session and server baselines.
	// EXAMINE must preserve Recent for both later opens in this session and other
	// sessions (RFC 3501 §6.3.2); the same applies to ACL read-only SELECT.
	if !isReadOnly {
		s.lastSelectedMailboxID = mailbox.ID
		if currentSummary.UIDNext > 0 {
			s.lastHighestUID = imap.UID(currentSummary.UIDNext - 1)
		} else {
			s.lastHighestUID = 0
		}
		if s.lastHighestUID > 0 {
			s.server.mailboxRecentUIDs.Store(mailbox.ID, s.lastHighestUID)
		}
	}

	s.currentNumMessages.Store(uint32(currentSummary.NumMessages))
	s.currentHighestModSeq.Store(currentSummary.HighestModSeq)
	s.reportedHighestModSeq.Store(currentSummary.HighestModSeq)
	s.reportedModSeqGap.Store(false)
	s.queuedFlagUpdates.Store(false)

	s.firstUnseenSeqNum.Store(firstUnseenSeqNum)
	if firstUnseenSeqNum > 0 {
		s.DebugLog("first unseen message dynamically bound", "seq", firstUnseenSeqNum)
	}

	s.selectedMailbox = mailbox
	// RFC 3501 §6.3.2: remember whether the mailbox was opened with EXAMINE so
	// mutating commands (STORE, EXPUNGE) can be rejected on a read-only selection.
	s.selectedReadOnly.Store(isReadOnly)
	// RFC 9051 §6.3.3: EXAMINE itself, which also keeps FETCH from setting \Seen.
	s.selectedExamined.Store(examined)
	s.mailboxTracker = imapserver.NewMailboxTracker(s.currentNumMessages.Load())
	s.sessionTracker = s.mailboxTracker.NewSession()
	s.savedSearchUIDs = nil // RFC 5182: the "$" saved result is reset on mailbox change

	// Track domain and user command activity
	if s.IMAPUser != nil {
		metrics.TrackDomainCommand("imap", s.IMAPUser.Address.Domain(), "SELECT")
		metrics.TrackUserActivity("imap", s.IMAPUser.Address.FullAddress(), "command", 1)
	}

	// After EXAMINE "No changes to the permanent state of the mailbox, including
	// per-user state, are permitted" (RFC 9051 §6.3.3), so no flag is permanent
	// there. The response is still sent, with an empty list as in the §6.3.3
	// example: without it "the client should assume that all flags can be
	// changed permanently" (§6.3.2).
	var permanentFlags []imap.Flag
	if !examined {
		permanentFlags = getPermanentFlags(userRights)
	}

	selectData := &imap.SelectData{
		// Flags defined for this mailbox (system flags, common keywords, and in-use custom flags)
		Flags: displayFlags,
		// Flags that can be changed, restricted to the user's flag rights (RFC 4314 §5.1.1)
		PermanentFlags: permanentFlags,
		// RFC 4314 §5.2: SELECT is READ-ONLY when the user holds none of the rights
		// that permit modifying the mailbox — insert ('i'), expunge ('e'), or the
		// shared-flag rights (Sora shares all flags: 's','t','w').
		ReadOnly:          isReadOnly,
		NumMessages:       s.currentNumMessages.Load(),
		UIDNext:           imap.UID(currentSummary.UIDNext),
		UIDValidity:       s.selectedMailbox.UIDValidity,
		NumRecent:         numRecent,
		FirstUnseenSeqNum: s.firstUnseenSeqNum.Load(),
	}

	// Only include HighestModSeq if CONDSTORE capability is enabled
	if s.GetCapabilities().Has(imap.CapCondStore) {
		selectData.HighestModSeq = s.currentHighestModSeq.Load()
	}

	// Handle QRESYNC parameter if provided
	// RFC 7162 §3.2.5: QRESYNC SELECT parameter for efficient resynchronization
	// Note: options.QResync is only populated by imapserver if ENABLE QRESYNC was sent
	if options != nil && options.QResync != nil {
		qr := options.QResync
		s.DebugLog("processing QRESYNC SELECT", "uidvalidity", qr.UIDValidity, "modseq", qr.ModSeq)

		// Validate UIDValidity matches current mailbox
		// RFC 7162 §3.2.5: If UIDVALIDITY doesn't match, client must resync from scratch
		if qr.UIDValidity != s.selectedMailbox.UIDValidity {
			s.DebugLog("QRESYNC UIDVALIDITY mismatch", "client", qr.UIDValidity, "server", s.selectedMailbox.UIDValidity)
			// Don't return error - just omit VANISHED/Modified responses
			// Client will detect mismatch and perform full resync
			return selectData, nil
		}

		if len(vanishedUIDs) > 0 {
			// Convert UIDs to optimized ranges
			selectData.Vanished = convertUIDsToRanges(vanishedUIDs)
			s.DebugLog("QRESYNC VANISHED", "count", len(vanishedUIDs), "ranges", len(selectData.Vanished))
		}

		if len(changedMsgs) > 0 {
			// Build Modified slice with sequence numbers
			selectData.Modified = make([]imap.SelectModifiedData, 0, len(changedMsgs))

			// For QRESYNC, we report messages that still exist (not expunged)
			for _, msg := range changedMsgs {
				if msg.SeqNum == 0 {
					s.WarnLog("skipping modified message with invalid sequence number 0", "uid", msg.UID)
					continue
				}
				selectData.Modified = append(selectData.Modified, imap.SelectModifiedData{
					SeqNum: msg.SeqNum,
					UID:    msg.UID,
					Flags:  msg.Flags,
					ModSeq: msg.ModSeq,
				})
			}
			s.DebugLog("QRESYNC Modified", "count", len(selectData.Modified))
		}
	}

	return selectData, nil
}

func (s *IMAPSession) Unselect(ctx context.Context) error {
	// If the session is closing, don't try to unselect.
	if ctx.Err() != nil {
		s.DebugLog("session context is cancelled, skipping unselect")
		return nil
	}

	acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout(ctx)
	if !acquired {
		s.WarnLog("failed to acquire write lock within timeout")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}
	defer release()

	if s.selectedMailbox != nil {
		s.DebugLog("mailbox cleared from session state", "mailbox", s.selectedMailbox.Name, "mailbox_id", s.selectedMailbox.ID)
		// The s.lastSelectedMailboxID and s.lastHighestUID fields are intentionally *not* cleared here.
		// They hold the state of the mailbox that was just active, so the next Select
		// can use them to determine "new" messages for that specific mailbox.
	}
	s.clearSelectedMailboxStateLocked()
	return nil
}
