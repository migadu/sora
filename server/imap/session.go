package imap

import (
	"context"
	"fmt"
	"sync"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	_ "github.com/emersion/go-message/charset"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server"
)

type IMAPSession struct {
	server.Session
	*IMAPUser
	server *IMAPServer
	conn   *imapserver.Conn
	ctx    context.Context
	cancel context.CancelFunc
	mutex  sync.RWMutex

	selectedMailbox *db.DBMailbox
	mailboxTracker  *imapserver.MailboxTracker
	sessionTracker  *imapserver.SessionTracker

	currentHighestModSeq uint64
	currentNumMessages   uint32

	lastSelectedMailboxID int64
	lastHighestUID        imap.UID
}

func (s *IMAPSession) Context() context.Context {
	return s.ctx
}

func (s *IMAPSession) internalError(format string, a ...interface{}) *imap.Error {
	s.Log(format, a...)
	return &imap.Error{
		Type: imap.StatusResponseTypeNo,
		Code: imap.ResponseCodeServerBug,
		Text: fmt.Sprintf(format, a...),
	}
}

func (s *IMAPSession) Close() error {
	if s == nil {
		return nil
	}
	// Use the session's primary mutex (from the embedded server.Session)
	// to protect modifications to IMAPSession fields and embedded Session fields.
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.IMAPUser != nil {
		s.Log("closing session for user: %v", s.IMAPUser.FullAddress())
		s.IMAPUser = nil
		s.Session.User = nil
	} else {
		s.Log("client dropped unauthenticated connection")
	}

	s.clearSelectedMailboxStateLocked()

	if s.cancel != nil {
		s.cancel()
	}

	return nil
}

func (s *IMAPSession) clearSelectedMailboxStateLocked() {
	if s.sessionTracker != nil {
		s.sessionTracker.Close()
	}
	s.selectedMailbox = nil
	s.mailboxTracker = nil
	s.sessionTracker = nil
	s.currentHighestModSeq = 0
	s.currentNumMessages = 0
}

// decodeNumSetLocked translates client sequence numbers to server sequence numbers.
// IMPORTANT: The caller MUST hold s.mutex (either read or write lock) when calling this method.
func (s *IMAPSession) decodeNumSetLocked(numSet imap.NumSet) imap.NumSet {
	if s.sessionTracker == nil {
		return numSet
	}

	seqSet, ok := numSet.(imap.SeqSet)
	if !ok {
		return numSet
	}

	// Use the session's current understanding of the total number of messages
	// to resolve '*' (represented by 0 in imap.SeqRange Start/Stop).
	// This count (s.currentNumMessages) is maintained by SELECT, APPEND (for this session),
	// and POLL, reflecting this session's potentially slightly delayed view of the mailbox.
	currentTotalMessagesInMailbox := s.currentNumMessages

	var out imap.SeqSet
	for _, seqRange := range seqSet {
		actualStart := seqRange.Start
		if seqRange.Start == 0 { // Represents '*' for the start of the range
			if currentTotalMessagesInMailbox == 0 {
				actualStart = 0 // Or 1, but 0 is fine; DecodeSeqNum(0) is 0.
			} else {
				actualStart = currentTotalMessagesInMailbox
			}
		}

		actualStop := seqRange.Stop
		if seqRange.Stop == 0 { // Represents '*' for the end of the range
			if currentTotalMessagesInMailbox == 0 {
				actualStop = 0
			} else {
				actualStop = currentTotalMessagesInMailbox
			}
		}

		// Convert resolved client-view sequence numbers to server-view sequence numbers.
		// s.sessionTracker.DecodeSeqNum handles mapping based on this session's
		// view of expunges. It returns 0 if the client-view number is invalid
		// (e.g., too high, or refers to an expunged message in this session's view).
		start := s.sessionTracker.DecodeSeqNum(actualStart)
		stop := s.sessionTracker.DecodeSeqNum(actualStop)

		// If actualStart was a specific non-zero number (not '*') but decodes to 0,
		// it means that specific sequence number is invalid from the server's perspective
		// for this session (e.g., message 100 requested, but only 50 exist or 100 was expunged).
		// In such a case, this part of the range is invalid.
		if start == 0 && seqRange.Start != 0 {
			continue
		}
		if stop == 0 && seqRange.Stop != 0 {
			continue
		}
		out = append(out, imap.SeqRange{Start: start, Stop: stop})
	}
	if len(out) == 0 && len(seqSet) > 0 {
		return imap.SeqSet{}
	}
	return out
}

// decodeNumSet translates client sequence numbers to server sequence numbers.
// It safely acquires the read mutex to protect access to session state.
func (s *IMAPSession) decodeNumSet(numSet imap.NumSet) imap.NumSet {
	// Acquire read mutex to protect access to session state
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Use the helper method that assumes the caller holds the lock
	return s.decodeNumSetLocked(numSet)
}
