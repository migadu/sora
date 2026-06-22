package imap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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
	sessionCaps    atomic.Value                                     // imap.CapSet - per-session capabilities after filtering (lock-free access)

	// Atomic counters for lock-free access
	currentHighestModSeq atomic.Uint64
	currentNumMessages   atomic.Uint32
	firstUnseenSeqNum    atomic.Uint32 // Sequence number of the first unseen message

	lastSelectedMailboxID int64
	lastHighestUID        imap.UID
	useMasterDB           atomic.Bool // Pin session to master DB after a write to ensure consistency

	// savedSearchUIDs holds the SEARCH RETURN (SAVE) result set referenced by
	// "$" (RFC 5182 / RFC 9051 §6.4.4.1). It is per-session, scoped to the
	// currently selected mailbox, stored as UIDs (stable across EXPUNGE), and
	// never persisted. Guarded by s.mutex; reset on every mailbox change.
	savedSearchUIDs imap.UIDSet

	// Memory tracking
	memTracker *server.SessionMemoryTracker

	// Session statistics for summary logging
	messagesAppended atomic.Uint32
	messagesExpunged atomic.Uint32
	messagesMoved    atomic.Uint32
	messagesCopied   atomic.Uint32
}

func (s *IMAPSession) Context() context.Context {
	return s.ctx
}

// GetCapabilities returns the effective capabilities for this session
// If session-specific capabilities haven't been set, it returns the server's default capabilities
func (s *IMAPSession) GetCapabilities() imap.CapSet {

	// If we have a pending JA4 connection, try to capture fingerprint now
	// This is a fallback path for when fingerprint wasn't available during NewSession
	if s.ja4Conn != nil && s.ja4Fingerprint == "" {
		if fingerprint, err := s.ja4Conn.GetJA4Fingerprint(); err == nil && fingerprint != "" {
			s.ja4Fingerprint = fingerprint
			s.ja4Conn = nil
			s.InfoLog("JA4 fingerprint captured during lazy evaluation", "fingerprint", s.ja4Fingerprint)

			// Re-initialize capabilities from server defaults
			caps := make(imap.CapSet)
			for cap := range s.server.caps {
				caps[cap] = struct{}{}
			}
			s.sessionCaps.Store(caps)

			s.applyCapabilityFilters()
		}
	}

	// Atomic load - safe for concurrent access
	// Return a copy to prevent concurrent modification issues
	if capsVal := s.sessionCaps.Load(); capsVal != nil {
		stored := capsVal.(imap.CapSet)
		// Make a defensive copy - maps are reference types!
		caps := make(imap.CapSet, len(stored))
		for k, v := range stored {
			caps[k] = v
		}
		return caps
	}

	// Fallback to server capabilities if not yet initialized
	return s.server.caps
}

// AppendLimit implements the SessionAppendLimit interface from go-imap.
// Returns the maximum size in bytes that can be uploaded in an APPEND command.
// The go-imap library uses this to:
// 1. Check literal size BEFORE reading data (prevents memory exhaustion)
// 2. For LITERAL+ (non-synchronizing), drain oversized data to prevent stream corruption
// 3. Advertise APPENDLIMIT=<size> capability to clients
func (s *IMAPSession) AppendLimit() uint32 {
	limit := s.server.appendLimit
	if limit <= 0 {
		limit = DefaultAppendLimit // 25MB fallback
	}
	return uint32(limit)
}

// SetClientID stores the client ID information and applies capability filtering
func (s *IMAPSession) SetClientID(clientID *imap.IDData) {
	s.clientID = clientID
	s.applyCapabilityFilters()
}

// applyCapabilityFilters applies client-specific capability filtering based on client ID and TLS fingerprint
func (s *IMAPSession) applyCapabilityFilters() {
	// Start with the server's full capability set
	caps := make(imap.CapSet)
	originalCapCount := len(s.server.caps)
	for cap := range s.server.caps {
		caps[cap] = struct{}{}
	}

	// Apply capability filtering based on client identification and/or TLS fingerprint
	disabledCaps := s.server.filterCapabilitiesForClient(caps, s.clientID, s.ja4Fingerprint)

	// Atomic store - safe for concurrent access
	s.sessionCaps.Store(caps)

	if len(disabledCaps) > 0 {
		var clientInfo string
		if s.clientID != nil {
			clientInfo = fmt.Sprintf("client %s %s", s.clientID.Name, s.clientID.Version)
		} else if s.ja4Fingerprint != "" {
			clientInfo = fmt.Sprintf("TLS fingerprint %s", s.ja4Fingerprint)
		} else {
			clientInfo = "unknown client"
		}
		s.InfoLog("capability filters applied", "client", clientInfo, "disabled", disabledCaps, "enabled", len(caps), "total", originalCapCount)
	}
}

func (s *IMAPSession) internalError(format string, a ...any) *imap.Error {
	// Format the error message once
	errorText := fmt.Sprintf(format, a...)
	// Log using structured logging with the formatted message
	s.InfoLog(errorText)

	// Extract the actual error from variadic args to check its type.
	// The error is typically passed as the last argument (e.g., "failed to do X: %v", err).
	var actualErr error
	for i := len(a) - 1; i >= 0; i-- {
		if err, ok := a[i].(error); ok {
			actualErr = err
			break
		}
	}

	// A canceled request context means the client went away mid-command. The
	// client will never read this response, and it is not a server fault, so
	// return a plain NO (no SERVERBUG/UNAVAILABLE code) — that keeps commandStatus
	// from counting it as a server_error or logging it at WARN. Note this is
	// distinct from context.DeadlineExceeded (a server-side timeout), which falls
	// through to the transient/[UNAVAILABLE] handling below.
	if actualErr != nil && errors.Is(actualErr, context.Canceled) {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Command aborted",
		}
	}

	// Detect transient infrastructure errors (DB exhaustion, circuit breakers,
	// storage failures, timeouts) and return [UNAVAILABLE] instead of [SERVERBUG]
	// so clients back off instead of retrying aggressively.
	//
	// db.ClassifyDBError bridges raw pgx errors (which use plain strings like
	// "too many clients") to our sentinel errors, making errors.Is() work.
	if actualErr != nil && isTransientError(db.ClassifyDBError(actualErr)) {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeUnavailable,
			Text: "Service temporarily unavailable, please try again later",
		}
	}

	return &imap.Error{
		Type: imap.StatusResponseTypeNo,
		Code: imap.ResponseCodeServerBug,
		Text: errorText,
	}
}

// classifyAndTrackError classifies IMAP errors and tracks them in metrics
func (s *IMAPSession) classifyAndTrackError(command string, err error, imapErr *imap.Error) {
	if err == nil && imapErr == nil {
		return
	}

	// A canceled request context means the client disconnected mid-command (a
	// server-side timeout surfaces as context.DeadlineExceeded, not Canceled).
	// That is the client's doing, not a protocol violation or server fault, so
	// don't record it in sora_protocol_errors_total or surface it at WARN —
	// otherwise normal client churn inflates the error rate operators alert on.
	if err != nil && errors.Is(err, context.Canceled) {
		s.DebugLog("command aborted by client disconnect", "command", command, "error", err)
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
		case imap.ResponseCodeUnavailable:
			errorType = "service_unavailable"
			severity = "server_error"
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
		var netErr net.Error
		isNetErr := errors.As(err, &netErr)
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			errorType = "timeout"
			severity = "server_error"
		case errors.Is(err, context.Canceled):
			errorType = "canceled"
			severity = "client_error"
		case errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || (isNetErr && !netErr.Timeout()):
			errorType = "network_error"
			severity = "client_error"
		case isNetErr && netErr.Timeout():
			errorType = "network_timeout"
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

	// Surface every tracked protocol error at WARN with the same labels exposed on
	// the sora_protocol_errors_total metric. Without this the counter increments
	// silently and operators can't correlate a rising metric (e.g. a client
	// repeatedly appending to a non-existent mailbox) with a concrete cause.
	// Prefer imapErr for the detail string: its Text carries the human-readable
	// context (such as the mailbox name) that the underlying err often lacks.
	detail := err
	if imapErr != nil {
		detail = imapErr
	}
	s.WarnLog("protocol error", "command", command, "error_type", errorType, "severity", severity, "error", detail)
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
	duration := time.Since(s.startTime)
	metrics.ConnectionDuration.WithLabelValues("imap", s.server.name, s.server.hostname).Observe(duration.Seconds())

	// Log and record peak memory usage
	if s.memTracker != nil {
		peak := s.memTracker.Peak()
		metrics.SessionMemoryPeakBytes.WithLabelValues("imap", s.server.name, s.server.hostname).Observe(float64(peak))
		if peak > 0 {
			s.InfoLog("session memory peak", "bytes", server.FormatBytes(peak))
		}
	}

	// Log session summary with statistics (similar to Dovecot)
	appended := s.messagesAppended.Load()
	expunged := s.messagesExpunged.Load()
	moved := s.messagesMoved.Load()
	copied := s.messagesCopied.Load()
	if appended > 0 || expunged > 0 || moved > 0 || copied > 0 {
		s.InfoLog("session summary",
			"duration", fmt.Sprintf("%.1fs", duration.Seconds()),
			"appended", appended,
			"expunged", expunged,
			"moved", moved,
			"copied", copied)
	}

	s.server.totalConnections.Add(-1)

	// Prometheus metrics - connection closed
	metrics.ConnectionsCurrent.WithLabelValues("imap", s.server.name, s.server.hostname).Dec()

	if s.IMAPUser != nil {
		s.server.authenticatedConnections.Add(-1)
		metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap", s.server.name, s.server.hostname).Dec()
		s.InfoLog("closing session")

		// Unregister connection from tracker
		s.unregisterConnection()

		s.IMAPUser = nil
		s.Session.User = nil
	} else {
		s.InfoLog("unauthenticated connection dropped")
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
	s.savedSearchUIDs = nil // saved "$" result is scoped to the selected mailbox
}

// setSavedSearchResult stores the SEARCH RETURN (SAVE) result set (RFC 5182).
// Called outside any held mutex; acquires the write lock for a quick assignment.
func (s *IMAPSession) setSavedSearchResult(uids imap.UIDSet) {
	s.mutex.Lock()
	s.savedSearchUIDs = uids
	s.mutex.Unlock()
}

// savedSearchResultLocked returns a copy of the saved "$" result set.
// The caller MUST hold s.mutex (read or write lock).
func (s *IMAPSession) savedSearchResultLocked() imap.UIDSet {
	if len(s.savedSearchUIDs) == 0 {
		return imap.UIDSet{}
	}
	out := make(imap.UIDSet, len(s.savedSearchUIDs))
	copy(out, s.savedSearchUIDs)
	return out
}

// decodeNumSetLocked translates client sequence numbers to server sequence numbers.
// IMPORTANT: The caller MUST hold s.mutex (either read or write lock) when calling this method.
func (s *IMAPSession) decodeNumSetLocked(numSet imap.NumSet) imap.NumSet {
	// RFC 5182 / RFC 9051 §6.4.4.1: resolve the "$" saved-search-result marker to
	// this session's saved UID set (empty if nothing has been saved). The marker
	// is always a UIDSet, so the result bypasses sequence-number translation.
	if imap.IsSearchRes(numSet) {
		return s.savedSearchResultLocked()
	}

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

		// Use the sequence numbers directly without decoding.
		// In our database-authoritative design, the database maintains canonical sequence
		// numbers via triggers, and client sequence numbers should match database sequences.
		// We don't use DecodeSeqNum because:
		// 1. Database triggers immediately renumber sequences after expunge
		// 2. Clients receive expunge notifications to stay in sync
		// 3. DecodeSeqNum would double-adjust for expunges already reflected in the database
		start := actualStart
		stop := actualStop

		// Validate the range is non-zero and within bounds
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
		s.DebugLog("session context cancelled, skipping decodeNumSet")
		// Return unmodified set if context is cancelled
		return numSet
	}

	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.DebugLog("failed to acquire read lock for decodeNumSet within timeout")
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
		s.InfoLog("warmup skipped, no user in session")
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
		s.InfoLog("cache warmup trigger failed", "error", err)
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
			s.InfoLog("connection registration rejected", "error", err)
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
			s.InfoLog("failed to unregister connection", "error", err)
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
			s.InfoLog("connection kicked, disconnecting user")
			s.conn.NetConn().Close()
		case <-s.ctx.Done():
			// Session ended normally
		}
	}()
}
