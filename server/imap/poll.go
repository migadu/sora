package imap

import (
	"context"
	"errors"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
)

func (s *IMAPSession) Poll(ctx context.Context, w *imapserver.UpdateWriter, allowExpunge bool) error {
	// If the session is closing, don't try to poll.
	if ctx.Err() != nil {
		s.DebugLog("session context is cancelled, skipping poll")
		return nil
	}

	// Moving the cursor and delivering the tracker's updates renumber the
	// client's messages, which no command may see happen halfway (seqViewMu).
	s.seqViewMu.Lock()
	defer s.seqViewMu.Unlock()

	// First phase: Read state with read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		s.DebugLog("failed to acquire read lock within timeout")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}

	if s.selectedMailbox == nil || s.mailboxTracker == nil || s.sessionTracker == nil {
		release()
		return nil
	}
	mailboxID := s.selectedMailbox.ID
	highestModSeqToPollFrom := s.currentHighestModSeq.Load()
	release()

	// Hold off while a STORE of this session, or a FETCH that implicitly sets
	// \Seen, is between its write and its own FETCH responses (the NOTIFY pump
	// polls concurrently), so the delta read below either precedes that write
	// or finds it in ownStoreEcho.
	//
	// The lock is held until the updates this Poll queues are written, not
	// only queued. The tracker hands them over in one batch: while that batch
	// is being written to a slow client, a STORE or FETCH answer recorded in
	// ownStoreEcho could otherwise be written ahead of an older state of the
	// same row still in the batch, and that older state would be the last the
	// client receives. (Updates still queued in the tracker are the other
	// half: an answer records nothing while there are any, see
	// implicitSeenAnswer.expect.)
	s.ownStoreMu.Lock()
	defer s.ownStoreMu.Unlock()

	// Create a context that signals to use the master DB if the session is pinned.
	readCtx := ctx
	if s.useMasterDB.Load() {
		readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	}

	poll, err := s.server.rdb.PollMailboxWithRetry(readCtx, mailboxID, highestModSeqToPollFrom)
	if err != nil {
		// If mailbox was deleted, clear the selected mailbox state and return nil
		// The next command that requires a selected mailbox will fail with "No mailbox selected"
		if errors.Is(err, db.ErrMailboxNotFound) {
			s.WarnLog("selected mailbox was deleted, clearing selection", "mailbox_id", mailboxID)
			// Acquire write lock to safely clear state
			acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout(ctx)
			if acquired {
				s.clearSelectedMailboxStateLocked()
				release()
			}
			return nil // Return success - no updates to send
		}

		// If the context was canceled (e.g. client disconnected), gracefully skip.
		if errors.Is(err, context.Canceled) {
			s.DebugLog("session context cancelled during database poll")
			return nil
		}

		return s.internalError("failed to poll mailbox: %v", err)
	}

	acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout(ctx)
	if !acquired {
		s.DebugLog("failed to acquire write lock within timeout")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}

	if s.selectedMailbox == nil || s.selectedMailbox.ID != mailboxID || s.mailboxTracker == nil || s.sessionTracker == nil {
		release()
		return nil
	}

	// Concurrency guard: the NOTIFY pump runs Poll concurrently with the
	// per-command Poll. Both may read the same cursor under the read lock,
	// fetch the same delta from the database, and reach here. Whoever takes
	// the write lock second would re-apply updates the first already
	// delivered — duplicate QueueExpunge (shifting the tracker's sequence
	// numbers) and duplicate unsolicited responses. If the cursor advanced
	// while we were unlocked, another Poll already handled this window; drop
	// our now-stale delta. The cursor is monotonic (never regresses), so an
	// inequality is a sufficient and safe check.
	if s.currentHighestModSeq.Load() != highestModSeqToPollFrom {
		release()
		s.DebugLog("skipping stale concurrent poll", "polled_from", highestModSeqToPollFrom, "current", s.currentHighestModSeq.Load())
		return nil
	}

	// Determine the highest MODSEQ from the updates processed in this poll.
	// Start with the MODSEQ we polled from, in case no updates are found. The
	// cursor also passes the messages created and expunged in this window, which
	// are not reported (MailboxPoll.PhantomModSeq): the cursor is the view the
	// client's sequence numbers are counted in (db.WithSeqView), and the client
	// never saw them.
	maxModSeqInThisPoll := highestModSeqToPollFrom
	if len(poll.Updates) > 0 {
		for _, update := range poll.Updates {
			if update.EffectiveModSeq > maxModSeqInThisPoll {
				maxModSeqInThisPoll = update.EffectiveModSeq
			}
		}
		s.currentHighestModSeq.Store(max(maxModSeqInThisPoll, poll.PhantomModSeq))
	} else if next := max(poll.ModSeq, poll.PhantomModSeq); next > highestModSeqToPollFrom {
		// If there were no specific message updates, update to the global current_modseq
		// to ensure the session eventually catches up if the mailbox is truly idle.
		//
		// The cursor must never move backwards: with multiple read replicas at
		// different lag, a poll answered by a laggier replica can report a
		// HIGHESTMODSEQ below the session cursor. Storing it would replay
		// updates the client already saw on the next poll — duplicate
		// unsolicited FETCHes at best, re-queued EXPUNGEs tripping the
		// desync-BYE path at worst.
		s.currentHighestModSeq.Store(next)
	}

	// A count increase is deliberately NOT queued here: it is queued by the final
	// reconciliation below, after the expunges. Ordering is load-bearing twice over.
	//
	// On the wire, RFC 3501 §7.4.1 bars EXPUNGE responses from FETCH/STORE/SEARCH, so
	// those commands poll with allowExpunge=false and SessionTracker.Poll emits the
	// leading non-expunge updates and stops at the first queued expunge. Queueing
	// EXISTS first therefore ships `* N EXISTS` while `* n EXPUNGE` stays behind, and
	// the client applies a larger total to a sequence space it was never told changed —
	// a silent seqnum desync that only heals on some later NOOP.
	//
	// In the tracker, db.PollMailbox numbers expunges in the client's *pre-poll* view
	// (created_modseq <= sinceModSeq), so those sequence numbers are only meaningful
	// while the count still excludes the messages appended in this same window.
	//
	// The EXISTS is deferred, never dropped: the reconciliation below always queues it,
	// and it reaches the client on the next expunge-permitting poll (NOOP/IDLE/CHECK).
	currentCount := s.currentNumMessages.Load()
	if poll.NumMessages < currentCount {
		// Database has fewer messages - check if there are expunge updates to explain it
		hasExpungeUpdates := false
		for _, update := range poll.Updates {
			if update.IsExpunge {
				hasExpungeUpdates = true
				break
			}
		}

		if !hasExpungeUpdates {
			// No expunge updates but database has fewer messages.
			// This can happen when:
			// 1. Messages were expunged between SELECT and first poll (missed in this poll)
			// 2. External deletion (direct DB manipulation)
			// 3. Replica lag
			// We'll handle this in the final reconciliation after processing updates
			s.DebugLog("database has fewer messages with no expunge updates in this poll",
				"session_count", currentCount, "db_count", poll.NumMessages,
				"will_reconcile_after_processing", true)
		}
	}

	// Group updates by sequence number to detect duplicate expunges
	expungedSeqNums := make(map[uint32]bool)
	skippedExpunges := 0

	// Track the mailbox tracker's expected message count as we process expunges.
	// The tracker starts with currentCount and decrements with each expunge.
	// We must not queue an expunge if it would make the tracker's count go negative.
	trackerExpectedCount := s.currentNumMessages.Load()

	// Process expunge updates
	for _, update := range poll.Updates {
		if !update.IsExpunge {
			continue
		}

		// Check if we've already processed an expunge for this sequence number
		if expungedSeqNums[update.SeqNum] {
			s.DebugLog("skipping duplicate expunge update", "seq", update.SeqNum, "uid", update.UID)
			skippedExpunges++
			continue
		}

		// Validate sequence number is within range of the tracker's current count
		// The tracker will panic if seqNum > tracker.numMessages, so we check against trackerExpectedCount
		if update.SeqNum == 0 || update.SeqNum > trackerExpectedCount {
			s.DebugLog("expunge sequence number out of range for tracker, skipping",
				"seq", update.SeqNum, "uid", update.UID,
				"tracker_messages", trackerExpectedCount,
				"session_messages", s.currentNumMessages.Load())
			skippedExpunges++
			continue
		}

		// Also check if tracker would go to zero and we have more expunges coming
		// This prevents trying to expunge from an already-empty tracker
		if trackerExpectedCount == 0 {
			s.DebugLog("skipping expunge because tracker is already at zero",
				"seq", update.SeqNum, "uid", update.UID)
			skippedExpunges++
			continue
		}

		s.DebugLog("processing expunge update", "seq", update.SeqNum, "uid", update.UID,
			"tracker_count_before", trackerExpectedCount)
		// RACE CONDITION PROTECTION: A concurrent Move handler may have already
		// called QueueExpunge for some of these messages, decrementing the tracker's
		// numMessages. If our sequence number is now out of range, the tracker panics.
		// We recover gracefully since the expunge was already handled.
		panicked := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
					s.DebugLog("skipping poll expunge (tracker already updated by concurrent operation)",
						"seq", update.SeqNum, "uid", update.UID, "panic", r)
				}
			}()
			s.mailboxTracker.QueueExpunge(update.SeqNum, update.UID)
		}()
		if panicked {
			skippedExpunges++
			continue
		}
		// Atomically decrement the current number of messages
		s.currentNumMessages.Add(^uint32(0)) // Equivalent to -1 for unsigned
		// Track that the mailbox tracker's count decreased
		trackerExpectedCount--
		// An expunged \Recent message leaves the RECENT count with it. The
		// mailbox's size changed, so the new count follows the EXPUNGE (RFC 3501
		// §7.3.2): unlike the message count, which the EXPUNGE decrements itself
		// (§7.4.1), nothing tells the client that its RECENT count dropped.
		if update.UID > s.recentAboveUID && s.numRecent > 0 {
			s.numRecent--
			s.recentUnsent.Store(true)
		}

		// Mark this sequence number as already expunged to prevent duplicates
		expungedSeqNums[update.SeqNum] = true
	}

	// Final reconciliation: ensure session count matches database count
	// After processing all expunge updates, the session count should match the database.
	finalCount := s.currentNumMessages.Load()
	if poll.NumMessages < finalCount {
		// Database has fewer messages than session after processing expunges.
		diff := finalCount - poll.NumMessages

		// Count actual expunge updates processed (not skipped)
		processedExpunges := 0
		for _, update := range poll.Updates {
			if update.IsExpunge && expungedSeqNums[update.SeqNum] {
				// This expunge was processed (marked in expungedSeqNums map)
				processedExpunges++
			}
			// Note: Skipped expunges (!expungedSeqNums[update.SeqNum]) are already counted in skippedExpunges
		}

		// Determine if the mismatch can be safely reconciled
		canReconcile := false
		reconcileReason := ""

		if skippedExpunges > 0 && diff <= uint32(skippedExpunges) {
			// Explained by skipped duplicate/out-of-range expunges
			canReconcile = true
			reconcileReason = "skipped_expunges"
		} else if processedExpunges == 0 && diff <= 10 {
			// Small diff with no expunges processed in this poll
			// Likely expunged between SELECT and first poll, or very old expunges
			// Safe to sync as long as difference is small (< 10 messages)
			canReconcile = true
			reconcileReason = "missed_old_expunges"
		} else if processedExpunges == 0 && finalCount > poll.NumMessages {
			// Large diff with no expunges in this poll's modseq window.
			// This can happen when:
			// 1. Background cleaner hard-deleted old expunged messages (outside modseq window)
			// 2. Bulk APPEND operations happened, then bulk hard-deletes occurred
			// 3. Multiple sessions expunging with session missing the notifications
			// Since the database is authoritative and we processed no expunges in this poll,
			// it's safe to sync down to the database count.
			s.WarnLog("large message count mismatch with no recent expunges, syncing to database",
				"session_count", finalCount, "db_count", poll.NumMessages, "diff", diff)
			canReconcile = true
			reconcileReason = "hard_deletes_outside_window"
		}

		if canReconcile {
			// The database has fewer messages than the tracker expects, but
			// we don't have EXPUNGE updates with the specific sequence numbers
			// that disappeared. This happens when expunged messages were
			// hard-deleted by the cleanup worker before this session polled —
			// the rows are gone, so the poll can't generate EXPUNGE events.
			// We can't call QueueExpunge without knowing which sequence numbers
			// to remove. Just updating currentNumMessages would desync it from
			// the tracker's internal count, causing subsequent FETCH commands
			// to resolve wrong UIDs.
			// Force reconnect so SELECT rebuilds the tracker from scratch.
			s.WarnLog("message count desync detected - forcing reconnect to rebuild tracker",
				"session_count", finalCount, "db_count", poll.NumMessages,
				"diff", diff, "reason", reconcileReason,
				"skipped_expunges", skippedExpunges, "processed_expunges", processedExpunges)
			release()
			return &imap.Error{
				Type: imap.StatusResponseTypeBye,
				Code: imap.ResponseCodeUnavailable,
				Text: "Mailbox state changed externally, please reconnect",
			}
		} else {
			// Large unexplained mismatch - unsafe to continue
			s.WarnLog("state desync: unexplained message count mismatch",
				"session_count", finalCount, "db_count", poll.NumMessages,
				"diff", diff, "skipped_expunges", skippedExpunges,
				"processed_expunges", processedExpunges)
			release()
			return &imap.Error{
				Type: imap.StatusResponseTypeBye,
				Code: imap.ResponseCodeUnavailable,
				Text: "Mailbox state changed externally, please reconnect",
			}
		}
	} else if poll.NumMessages > finalCount {
		// Database has more messages than expected - sync up
		// This is safe because new messages just get higher sequence numbers
		s.DebugLog("syncing message count up to database", "session_count", finalCount, "db_count", poll.NumMessages)

		// Protect against panic if tracker.numMessages > poll.NumMessages due to race
		panicOccurred := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicOccurred = true
					s.WarnLog("tracker desync detected when syncing message count up",
						"error", r,
						"final_count", finalCount,
						"db_count", poll.NumMessages,
						"mailbox_id", mailboxID)
				}
			}()
			s.mailboxTracker.QueueNumMessages(poll.NumMessages)
		}()

		// If we couldn't update the tracker due to desync, force disconnection
		if panicOccurred {
			s.WarnLog("forcing disconnection due to tracker desync")
			release()
			return &imap.Error{
				Type: imap.StatusResponseTypeBye,
				Code: imap.ResponseCodeUnavailable,
				Text: "Mailbox state changed externally, please reconnect",
			}
		}
		s.currentNumMessages.Store(poll.NumMessages)

		// RFC 3501 §7.3.2: RECENT "occurs ... if the size of the mailbox changes
		// (e.g., new messages)", so this EXISTS is followed by the RECENT count
		// (written once the EXISTS is, below). The new messages follow the
		// finalCount ones the client knew, and each one counts when it is above
		// recentAboveUID, the set SEARCH RECENT answers with. Normally that is
		// all of them; one another read-write session had already seen when this
		// SELECT read its baseline is not.
		for _, update := range poll.Updates {
			if !update.IsExpunge && update.SeqNum > finalCount && update.UID > s.recentAboveUID {
				s.numRecent++
			}
		}
		s.recentUnsent.Store(true)

		// RFC 3501 §2.3.2: a read-write session that is notified of a message is
		// the one that sees it as \Recent; later opens must not. Advance the same
		// baselines a read-write SELECT sets, so that EXAMINE/SELECT after this
		// point (here or in another session) does not count these messages again.
		// recentAboveUID is left alone: they stay \Recent in this session.
		if !s.selectedReadOnly.Load() && s.lastSelectedMailboxID == mailboxID && poll.HighestUID > 0 {
			s.lastHighestUID = max(s.lastHighestUID, poll.HighestUID)
			s.server.mailboxRecentUIDs.Store(mailboxID, poll.HighestUID)
		}
	}

	// Read the writer's actual NOTIFY policy once, when the first flag update
	// needs it. A nil backend watch can mean NOTIFY NONE as well as the
	// default, and only the library knows which policy its writer applies.
	var flagFilterRead, flagsFiltered bool
	recentAbove := s.recentFlagAboveLocked()
	for _, update := range poll.Updates {
		if update.IsExpunge {
			continue
		}

		// Already answered by this session's own STORE or FETCH.
		if modSeq, ok := s.ownStoreEcho[update.UID]; ok && modSeq == update.EffectiveModSeq && s.ownStoreEchoMailboxID == mailboxID {
			continue
		}
		if !flagFilterRead {
			flagsFiltered = !w.FlagChangeAllowed()
			flagFilterRead = true
		}
		// NOTIFY may discard this update instead of writing it. An empty
		// tracker then does not mean every change through the cursor was
		// reported: keep the preceding safe watermark for this selection,
		// even if the client enables FlagChange again later.
		if flagsFiltered {
			s.reportedModSeqGap.Store(true)
		} else {
			s.queuedFlagUpdates.Store(true)
		}

		allFlags := db.BitwiseToFlags(update.BitwiseFlags)
		if allFlags == nil {
			allFlags = []imap.Flag{}
		}
		for _, customFlag := range update.CustomFlags {
			allFlags = append(allFlags, imap.Flag(customFlag))
		}
		// Same filter FETCH and SELECT apply: a stored keyword that is not an
		// IMAP atom cannot be encoded, and an unsolicited FETCH carrying one
		// aborts the write and drops the session (helpers.IsValidFlagName).
		allFlags = withRecentFlag(helpers.SanitizeFlags(allFlags), update.UID, recentAbove)
		// Pass the change's modseq so CONDSTORE-aware sessions receive MODSEQ in the
		// unsolicited FETCH response (RFC 7162 §3.2); the writer omits it otherwise.
		s.mailboxTracker.QueueMessageFlags(update.SeqNum, update.UID, allFlags, update.EffectiveModSeq, nil)
	}

	// The session has now seen every change up to its cursor.
	cursor := s.currentHighestModSeq.Load()
	s.pruneOwnStoreEchoLocked(mailboxID, cursor)

	// Store sessionTracker reference before releasing lock to avoid race condition
	sessionTracker := s.sessionTracker
	numRecent := s.numRecent

	release() // Release the session lock before writing; ownStoreMu stays held (see above)

	// Check if sessionTracker is still valid after releasing lock
	if sessionTracker == nil {
		return nil
	}

	// The RECENT count goes out once the EXISTS or EXPUNGE that changed it has:
	// a FETCH, STORE or SEARCH holds an EXPUNGE back, and the EXISTS behind it,
	// and a later poll delivers them. Only with nothing left queued does the
	// client know the messages numRecent counts. go-imap writes no RECENT to an
	// IMAP4rev2 session.
	if err := sessionTracker.PollWith(w, allowExpunge, func() error {
		if sessionTracker.QueuedUpdates() == 0 && s.recentUnsent.Swap(false) {
			return w.WriteNumRecent(numRecent)
		}
		return nil
	}); err != nil {
		return err
	}
	// Every change up to the cursor has been queued, by this poll or an earlier
	// one. Any flag update queued behind a withheld EXPUNGE stays queued until
	// the tracker drains completely, so checking FlagChangeAllowed here catches
	// a NOTIFY filter installed between queueing and delivery. Once nothing is
	// left queued, and no NOTIFY filter consumed a flag change without
	// reporting it, all of them have been sent. Polls run one at a time
	// (seqViewMu) and the cursor never moves back.
	if sessionTracker.QueuedUpdates() == 0 {
		if s.queuedFlagUpdates.Swap(false) && !w.FlagChangeAllowed() {
			s.reportedModSeqGap.Store(true)
		}
		if !s.reportedModSeqGap.Load() {
			s.reportedHighestModSeq.Store(cursor)
		}
	}
	return nil
}

var _ imapserver.SessionHighestModSeq = (*IMAPSession)(nil)

// HighestModSeq implements imapserver.SessionHighestModSeq: the HIGHESTMODSEQ the
// first CONDSTORE enabling command with a mailbox selected returns (RFC 7162
// §3.1), and the one written after a command whose MODSEQ FETCH data items went
// past it, such as a STORE answered while another session's VANISHED is held
// back (RFC 7162 §3.2). The poll cursor is not it: it also covers what a FETCH,
// STORE or SEARCH left queued, an EXPUNGE they may not send and whatever
// follows it, and the client adopts the value "even if it has seen higher
// mod-sequences" (RFC 7162 §6), so it would skip those changes if it
// resynchronized from it. A flag
// change consumed under a NOTIFY filter also holds this value back until a
// new SELECT: changing the filter does not replay the consumed flag update.
func (s *IMAPSession) HighestModSeq() uint64 {
	return s.reportedHighestModSeq.Load()
}

// pruneOwnStoreEchoLocked forgets the rows this session's own STORE and FETCH
// answers recorded that Poll has now passed: all of them when they were
// recorded in another mailbox, otherwise each one at or below cursor. A map
// left empty is dropped rather than kept: Go never shrinks a map, so a STORE
// over a large mailbox would otherwise hold its buckets (up to
// maxFetchSeenEchoEntries rows) for as long as the mailbox stays selected. The
// caller holds ownStoreMu.
func (s *IMAPSession) pruneOwnStoreEchoLocked(mailboxID int64, cursor uint64) {
	if s.ownStoreEchoMailboxID != mailboxID {
		s.ownStoreEcho = nil
		return
	}
	for uid, modSeq := range s.ownStoreEcho {
		if modSeq <= cursor {
			delete(s.ownStoreEcho, uid)
		}
	}
	if len(s.ownStoreEcho) == 0 {
		s.ownStoreEcho = nil
	}
}
