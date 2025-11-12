package imap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	_ "github.com/emersion/go-message/charset"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
)

type IMAPSession struct {
	server.Session
	*IMAPUser
	server      *IMAPServer
	conn        *imapserver.Conn
	ctx         context.Context
	cancel      context.CancelFunc
	mutex       sync.RWMutex
	mutexHelper *server.MutexTimeoutHelper
	releaseConn func() // Function to release connection from limiter
	startTime   time.Time

	inboxWarmupDone atomic.Bool // Ensures warmup runs only once
	selectedMailbox *db.DBMailbox
	mailboxTracker  *imapserver.MailboxTracker
	sessionTracker  *imapserver.SessionTracker

	// Client identification and capability filtering
	clientID       *imap.IDData
	ja4Fingerprint string                                           // JA4 TLS fingerprint
	ja4Conn        interface{ GetJA4Fingerprint() (string, error) } // Reference to JA4 conn if fingerprint not yet available
	sessionCaps    imap.CapSet                                      // Per-session capabilities after filtering

	// Atomic counters for lock-free access
	currentHighestModSeq atomic.Uint64
	currentNumMessages   atomic.Uint32
	firstUnseenSeqNum    atomic.Uint32 // Sequence number of the first unseen message

	lastSelectedMailboxID int64
	lastHighestUID        imap.UID
	useMasterDB           bool // Pin session to master DB after a write to ensure consistency

	// Memory tracking
	memTracker *server.SessionMemoryTracker
}

func (s *IMAPSession) Context() context.Context {
	return s.ctx
}

// GetCapabilities returns the effective capabilities for this session
// If session-specific capabilities haven't been set, it returns the server's default capabilities
// GetCapabilities returns the effective capabilities for this session
// If session-specific capabilities haven't been set, it returns the server's default capabilities
// GetCapabilities returns the effective capabilities for this session
func (s *IMAPSession) GetCapabilities() imap.CapSet {

	// If we have a pending JA4 connection, try to capture fingerprint now
	// This is a fallback path for when fingerprint wasn't available during NewSession
	if s.ja4Conn != nil && s.ja4Fingerprint == "" {
		if fingerprint, err := s.ja4Conn.GetJA4Fingerprint(); err == nil && fingerprint != "" {
			s.ja4Fingerprint = fingerprint
			s.ja4Conn = nil
			s.InfoLog("[JA4] Captured fingerprint during lazy evaluation: %s", s.ja4Fingerprint)

			// Re-initialize capabilities from server defaults
			s.sessionCaps = make(imap.CapSet)
			for cap := range s.server.caps {
				s.sessionCaps[cap] = struct{}{}
			}

			s.applyCapabilityFilters()
		}
	}

	return s.sessionCaps
}

// SetClientID stores the client ID information and applies capability filtering
func (s *IMAPSession) SetClientID(clientID *imap.IDData) {
	s.clientID = clientID
	s.applyCapabilityFilters()
}

// applyCapabilityFilters applies client-specific capability filtering based on client ID and TLS fingerprint
func (s *IMAPSession) applyCapabilityFilters() {
	// Start with the server's full capability set
	s.sessionCaps = make(imap.CapSet)
	originalCapCount := len(s.server.caps)
	for cap := range s.server.caps {
		s.sessionCaps[cap] = struct{}{}
	}

	// Apply capability filtering based on client identification and/or TLS fingerprint
	disabledCaps := s.server.filterCapabilitiesForClient(s.sessionCaps, s.clientID, s.ja4Fingerprint)

	if len(disabledCaps) > 0 {
		var clientInfo string
		if s.clientID != nil {
			clientInfo = fmt.Sprintf("client %s %s", s.clientID.Name, s.clientID.Version)
		} else if s.ja4Fingerprint != "" {
			clientInfo = fmt.Sprintf("TLS fingerprint %s", s.ja4Fingerprint)
		} else {
			clientInfo = "unknown client"
		}
		s.InfoLog("Applied capability filters for %s: disabled %v, %d/%d capabilities enabled",
			clientInfo, disabledCaps, len(s.sessionCaps), originalCapCount)
	}
}

func (s *IMAPSession) internalError(format string, a ...any) *imap.Error {
	s.InfoLog(format, a...)
	return &imap.Error{
		Type: imap.StatusResponseTypeNo,
		Code: imap.ResponseCodeServerBug,
		Text: fmt.Sprintf(format, a...),
	}
}

// classifyAndTrackError classifies IMAP errors and tracks them in metrics
func (s *IMAPSession) classifyAndTrackError(command string, err error, imapErr *imap.Error) {
	if err == nil && imapErr == nil {
		return
	}

	var errorType, severity string

	if imapErr != nil {

		// Classify based on IMAP error code and type
		switch imapErr.Code {
		case imap.ResponseCodeAuthenticationFailed:
			errorType = "auth_failed"
			severity = "client_error"
		case imap.ResponseCodeServerBug:
			errorType = "server_bug"
			severity = "server_error"
		case imap.ResponseCodeTryCreate:
			errorType = "mailbox_not_found"
			severity = "client_error"
		case imap.ResponseCodeNonExistent:
			errorType = "not_found"
			severity = "client_error"
		case imap.ResponseCodeTooBig:
			errorType = "message_too_big"
			severity = "client_error"
		default:
			if imapErr.Type == imap.StatusResponseTypeBad {
				errorType = "invalid_command"
				severity = "client_error"
			} else {
				errorType = "unknown"
				severity = "server_error"
			}
		}
	} else if err != nil {
		// Classify based on underlying error
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			errorType = "timeout"
			severity = "server_error"
		case errors.Is(err, context.Canceled):
			errorType = "canceled"
			severity = "client_error"
		case errors.Is(err, os.ErrPermission):
			errorType = "permission_denied"
			severity = "server_error"
		default:
			if errors.Is(err, consts.ErrMailboxNotFound) || errors.Is(err, consts.ErrDBNotFound) || errors.Is(err, consts.ErrMessageNotAvailable) {
				errorType = "not_found"
				severity = "client_error"
			} else {
				errorType = "unknown"
				severity = "server_error"
			}
		}
	}

	metrics.ProtocolErrors.WithLabelValues("imap", command, errorType, severity).Inc()
}

func (s *IMAPSession) Close() error {
	if s == nil {
		return nil
	}
	// Use the session's primary mutex (from the embedded server.Session)
	// to protect modifications to IMAPSession fields and embedded Session fields.
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Untrack connection from active connections
	if s.conn != nil {
		s.server.untrackConnection(s.conn)
	}

	// Release connection from limiter
	if s.releaseConn != nil {
		s.releaseConn()
		s.releaseConn = nil
	}

	// Observe connection duration
	metrics.ConnectionDuration.WithLabelValues("imap").Observe(time.Since(s.startTime).Seconds())

	// Log and record peak memory usage
	if s.memTracker != nil {
		peak := s.memTracker.Peak()
		metrics.SessionMemoryPeakBytes.WithLabelValues("imap").Observe(float64(peak))
		if peak > 0 {
			s.InfoLog("session memory - peak: %s", server.FormatBytes(peak))
		}
	}

	totalCount := s.server.totalConnections.Add(-1)
	var authCount int64 = 0

	// Prometheus metrics - connection closed
	metrics.ConnectionsCurrent.WithLabelValues("imap").Dec()

	if s.IMAPUser != nil {
		authCount = s.server.authenticatedConnections.Add(-1)
		metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap").Dec()
		s.InfoLog("closing session for user: %v (connections: total=%d, authenticated=%d)",
			s.IMAPUser.FullAddress(), totalCount, authCount)

		// Unregister connection from tracker
		s.unregisterConnection()

		s.IMAPUser = nil
		s.Session.User = nil
	} else {
		authCount = s.server.authenticatedConnections.Load()
		s.InfoLog("client dropped unauthenticated connection (connections: total=%d, authenticated=%d)",
			totalCount, authCount)
	}

	s.clearSelectedMailboxStateLocked()

	if s.cancel != nil {
		s.cancel()
	}

	// Mark session as done in WaitGroup for graceful drain
	s.server.sessionsWg.Done()

	return nil
}

func (s *IMAPSession) clearSelectedMailboxStateLocked() {
	if s.sessionTracker != nil {
		s.sessionTracker.Close()
	}
	s.selectedMailbox = nil
	s.mailboxTracker = nil
	s.sessionTracker = nil
	s.currentHighestModSeq.Store(0)
	s.currentNumMessages.Store(0)
	s.firstUnseenSeqNum.Store(0)
}

// decodeNumSetLocked translates client sequence numbers to server sequence numbers.
// IMPORTANT: The caller MUST hold s.mutex (either read or write lock) when calling this method.
func (s *IMAPSession) decodeNumSetLocked(numSet imap.NumSet) imap.NumSet {
	if s.sessionTracker == nil {
		return numSet
	}

	// Only handle SeqSet, not UIDSet - UIDs don't need sequence number translation

	seqSet, ok := numSet.(imap.SeqSet)
	if !ok {
		return numSet
	}

	// Use the session's current understanding of the total number of messages
	// to resolve '*' (represented by 0 in imap.SeqRange Start/Stop).
	// This count (s.currentNumMessages) is maintained by SELECT, APPEND (for this session),
	// and POLL, reflecting this session's potentially slightly delayed view of the mailbox.
	currentTotalMessagesInMailbox := s.currentNumMessages.Load()

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
	// Acquire read mutex with timeout to protect access to session state
	if s.ctx.Err() != nil {
		s.DebugLog("[DECODE] Session context is cancelled, skipping decodeNumSet.")
		// Return unmodified set if context is cancelled
		return numSet
	}

	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.DebugLog("[DECODE] Failed to acquire read lock for decodeNumSet within timeout")
		// Return unmodified set if we can't acquire the lock
		return numSet
	}
	defer release()

	// Use the helper method that assumes the caller holds the lock
	return s.decodeNumSetLocked(numSet)
}

// triggerCacheWarmup starts the cache warmup process if configured.
// It uses the server's warmup settings and ensures it only runs once per session.
func (s *IMAPSession) triggerCacheWarmup() {
	if s.IMAPUser == nil {
		s.InfoLog("warmup skipped: no user in session")
		return // Should not happen if called after authentication
	}

	// Check if warmup is enabled on the server
	if !s.server.enableWarmup {
		return
	}

	// Ensure warmup runs only once per session
	if !s.inboxWarmupDone.CompareAndSwap(false, true) {
		return
	}

	// Call the server's main warmup logic, which handles async execution
	// Use server appCtx instead of session ctx so warmup continues even if connection drops
	err := s.server.WarmupCache(s.server.appCtx, s.AccountID(), s.server.warmupMailboxes, s.server.warmupMessageCount, s.server.warmupAsync)
	if err != nil {
		// The WarmupCache method already logs its own errors, so just log a generic failure here.
		s.InfoLog("cache warmup trigger failed: %v", err)
	}
}

// registerConnection registers the connection in the connection tracker
func (s *IMAPSession) registerConnection(email string) error {
	if s.server.connTracker != nil && s.IMAPUser != nil {
		// Use configured database query timeout for connection tracking (database INSERT)
		queryTimeout := s.server.rdb.GetQueryTimeout()
		ctx, cancel := context.WithTimeout(s.ctx, queryTimeout)
		defer cancel()

		clientAddr := server.GetAddrString(s.conn.NetConn().RemoteAddr())

		if err := s.server.connTracker.RegisterConnection(ctx, s.AccountID(), email, "IMAP", clientAddr); err != nil {
			s.InfoLog("rejected connection registration: %v", err)
			return err
		}
	}
	return nil
}

// unregisterConnection removes the connection from the connection tracker
func (s *IMAPSession) unregisterConnection() {
	if s.server.connTracker != nil && s.IMAPUser != nil {
		// Use configured database query timeout for connection tracking (database DELETE)
		queryTimeout := s.server.rdb.GetQueryTimeout()
		ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
		defer cancel()

		clientAddr := server.GetAddrString(s.conn.NetConn().RemoteAddr())

		if err := s.server.connTracker.UnregisterConnection(ctx, s.AccountID(), "IMAP", clientAddr); err != nil {
			s.InfoLog("Failed to unregister connection: %v", err)
		}
	}
}

// startTerminationPoller starts a goroutine that waits for kick notifications
func (s *IMAPSession) startTerminationPoller() {
	if s.server.connTracker == nil || s.IMAPUser == nil {
		return
	}

	// Register session for kick notifications and get a channel that closes on kick
	kickChan := s.server.connTracker.RegisterSession(s.AccountID())

	go func() {
		// Unregister when done
		defer s.server.connTracker.UnregisterSession(s.AccountID(), kickChan)

		select {
		case <-kickChan:
			// Kick notification received - close connection
			s.InfoLog("Connection kicked - disconnecting user")
			s.conn.NetConn().Close()
		case <-s.ctx.Done():
			// Session ended normally
		}
	}()
}
