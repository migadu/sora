package imap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/emersion/go-message/charset"
	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
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
	closed      bool // Close has run; guarded by mutex

	// trackedClientAddr is the client address this session was registered
	// with in the connection tracker, so it is unregistered under the same
	// key even if an ID after login changed RemoteIP.
	trackedClientAddr string

	checkedIdleTimeout time.Duration // the idle timeout this connection's checker enforces (the IDLE keepalive beats it)

	inboxWarmupDone atomic.Bool // Ensures warmup runs only once
	selectedMailbox *db.DBMailbox
	mailboxTracker  *imapserver.MailboxTracker
	sessionTracker  *imapserver.SessionTracker

	// Client identification and capability filtering
	clientID       *imap.IDData
	ja4Fingerprint string                                           // JA4 TLS fingerprint
	ja4Conn        interface{ GetJA4Fingerprint() (string, error) } // Reference to JA4 conn if fingerprint not yet available
	sessionCaps    atomic.Value                                     // imap.CapSet - per-session capabilities after filtering (lock-free access); never modified once stored

	// Atomic counters for lock-free access
	currentHighestModSeq atomic.Uint64
	currentNumMessages   atomic.Uint32
	firstUnseenSeqNum    atomic.Uint32 // Sequence number of the first unseen message

	// reportedHighestModSeq is the mod-sequence up to which every change of
	// the selected mailbox has been sent to the client (HighestModSeq): the
	// SELECT's value, then the cursor of the last poll that left nothing
	// queued.
	reportedHighestModSeq atomic.Uint64
	// A NOTIFY filter can consume a flag change without sending it. The
	// report then stays conservative until SELECT establishes a new baseline;
	// enabling FlagChange again does not replay the consumed change.
	reportedModSeqGap atomic.Bool
	// queuedFlagUpdates records that the tracker holds a flag update queued
	// while FlagChange was allowed, so draining it after NOTIFY suppresses
	// FlagChange still marks reportedModSeqGap.
	queuedFlagUpdates atomic.Bool

	lastSelectedMailboxID int64
	lastHighestUID        imap.UID
	recentAboveUID        imap.UID    // Messages above this UID are \Recent in this session (RFC 3501 §2.3.2); set by SELECT
	numRecent             uint32      // The RECENT count: messages above recentAboveUID in the server view (currentNumMessages); set by SELECT, moved by Poll
	recentUnsent          atomic.Bool // Poll grew the mailbox or expunged a \Recent message and has not yet written the RECENT count that goes with that EXISTS or EXPUNGE
	useMasterDB           atomic.Bool // Pin session to master DB after a write to ensure consistency
	selectedReadOnly      atomic.Bool // True when the selected mailbox is read-only: opened with EXAMINE, or SELECTed without any of the 'iestw' rights
	selectedExamined      atomic.Bool // True when the selected mailbox was opened with EXAMINE itself (RFC 9051 §6.3.3)

	// A STORE answers its rows itself: with FETCH (FLAGS) when not .SILENT
	// (RFC 9051 §6.4.6), with FETCH (UID MODSEQ) for a CONDSTORE .SILENT
	// (RFC 7162 §3.1.3). So does a FETCH that implicitly sets \Seen, with
	// FLAGS in its own FETCH responses (RFC 9051 §6.4.5). ownStoreMu
	// serializes that STORE or FETCH with Poll so Poll can tell those rows
	// from foreign changes; it is taken before s.mutex, never while holding
	// it. ownStoreEcho maps each UID whose state the client has from such an
	// answer to that state's mod-sequence, in mailbox ownStoreEchoMailboxID;
	// Poll skips exactly those updates instead of reporting them again. Both
	// fields are guarded by ownStoreMu.
	ownStoreMu            sync.Mutex
	ownStoreEcho          map[imap.UID]uint64
	ownStoreEchoMailboxID int64
	fetchInFlight         int // metadata snapshots/responses in flight; guarded by ownStoreMu

	// seqViewMu keeps the client's sequence numbering still while a command
	// translates through it (seqView): the command holds it for reading from
	// before it reads the poll cursor and the tracker until its last response,
	// and Poll, which moves both and delivers what the tracker holds, holds it
	// for writing. Otherwise a NOTIFY pump poll during a command would number
	// the command's first responses in one view and the rest in another. It is
	// taken before ownStoreMu and s.mutex, and only once per command: a second
	// read lock queued behind a waiting Poll would deadlock.
	seqViewMu sync.RWMutex

	// savedSearchUIDs holds the SEARCH RETURN (SAVE) result set referenced by
	// "$" (RFC 5182 / RFC 9051 §6.4.4.1). It is per-session, scoped to the
	// currently selected mailbox, stored as UIDs (stable across EXPUNGE), and
	// never persisted. Guarded by s.mutex; reset on every mailbox change.
	savedSearchUIDs imap.UIDSet

	// NOTIFY (RFC 5465) watch state. notifyMutex guards the pointer swap:
	// SetNotify/Close write it on the command goroutine, NotifyPoll reads it
	// on the pump goroutine (the library stops the pump before SetNotify
	// runs, so the watch internals are only ever touched by one goroutine,
	// except the snapshot and the own changes commands record on the watch,
	// which notifyMutex guards as well).
	notifyMutex sync.Mutex
	notifyWatch *notifyWatch

	// Memory tracking
	memTracker *server.SessionMemoryTracker

	// BODY or BINARY section retained for <offset.size> chunk fetches (see body_section_cache.go).
	bodySectionCacheMu   sync.Mutex
	bodySectionCacheKey  string
	bodySectionCacheData []byte

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
//
// The set is returned as stored, not copied, like the server's set below, and
// callers must not modify it. No set is modified once stored in sessionCaps
// (NewSession, applyCapabilityFilters and the lazy JA4 path below each store a
// newly built one), so concurrent readers need no copy. Callers use it for a
// Has check, go-imap once per MODSEQ item it writes, and a copy allocated a
// map of the whole set for each (#1206).
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
	if capsVal := s.sessionCaps.Load(); capsVal != nil {
		return capsVal.(imap.CapSet)
	}

	// Fallback to server capabilities if not yet initialized
	return s.server.caps
}

// requireCapability refuses a command, or a command argument, that capability
// c adds when this session does not offer c. disabled_caps and client_filters
// take c out of CAPABILITY, but go-imap still hands the command to any session
// that implements it. The refusal is the one go-imap gives a session without
// the command: BAD, which RFC 9051 §6 lists for every command as "command
// unknown or arguments invalid".
func (s *IMAPSession) requireCapability(c imap.Cap, what string) error {
	if s.GetCapabilities().Has(c) {
		return nil
	}
	return &imap.Error{
		Type: imap.StatusResponseTypeBad,
		Code: imap.ResponseCodeClientBug,
		Text: what + " is not supported",
	}
}

// condStoreEnabled reports whether it is correct to emit a MODSEQ data item in a
// FETCH-style response for this session. Per RFC 7162 §3.2 that requires two things:
// the client must have become CONDSTORE-aware on this connection (issued a
// CONDSTORE-enabling command — tracked by go-imap), AND the session must still
// advertise CONDSTORE. A capability filter (e.g. for iOS) withdraws CONDSTORE only
// from a client that is not CONDSTORE-aware yet: one matched later leaves it in
// place (applyCapabilityFilters), since RFC 7162 §3.1 wants mod-sequences "until
// the connection is closed". Emitting MODSEQ to a client that never enabled
// CONDSTORE breaks strict parsers such as mbsync/isync.
func (s *IMAPSession) condStoreEnabled() bool {
	return s.conn != nil && s.conn.CondStoreEnabled() && s.GetCapabilities().Has(imap.CapCondStore)
}

// AdditionalCapabilities implements the imapserver.SessionAdditionalCaps interface.
// It returns extra, non-standard capability tokens (configured via additional_caps)
// that go-imap advertises verbatim in every CAPABILITY emission — including the
// unauthenticated greeting — bypassing its known-capability allowlist. This is how
// Sora advertises vendor tokens such as "X-ICEWARP-SERVER" for client server-type
// detection. Returns nil when none are configured (no extra tokens advertised).
func (s *IMAPSession) AdditionalCapabilities() []imap.Cap {
	return s.server.additionalCaps
}

// AppendLimit implements the SessionAppendLimit interface from go-imap.
// Returns the maximum size in bytes that can be uploaded in an APPEND command.
// The go-imap library uses this to:
// 1. Check literal size BEFORE reading data (prevents memory exhaustion)
// 2. For LITERAL+ (non-synchronizing), drain oversized data to prevent stream corruption
// 3. Advertise APPENDLIMIT=<size> capability to clients
//
// STATUS and LIST-STATUS report it as well. APPEND reads the whole literal into
// the session memory budget (readAppendLiteral), so the limit is never above
// that budget: go-imap then refuses a larger literal with NO [TOOBIG] before
// asking for it, instead of the session reading it and answering with an
// [UNAVAILABLE] that no retry cures.
// The budget is this session's own snapshot of session_memory_limit, which a
// reload changes for the sessions started after it.
func (s *IMAPSession) AppendLimit() uint32 {
	limit := s.server.appendLimit
	if s.memTracker != nil {
		if budget := s.memTracker.MaxAllowed(); budget > 0 && budget < int64(limit) {
			limit = uint32(budget)
		}
	}
	return limit
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

	// Capabilities already enabled on this connection cannot be withdrawn:
	// "Once enabled using ENABLE, each extension remains active until the IMAP
	// connection is closed" (RFC 9051 §6.3.1), and a CONDSTORE-aware client gets
	// mod-sequences "until the connection is closed" (RFC 7162 §3.1). Pass keep
	// into the filter pass so capabilities satisfied by keep are neither deleted
	// nor cascaded from (preserving e.g. ESORT/MULTISEARCH when ESEARCH stays
	// active via IMAP4rev2, or QRESYNC when CONDSTORE stays active).
	var keep imap.CapSet
	for c := range s.enabledCaps() {
		if _, offered := s.server.caps[c]; !offered {
			continue
		}
		if keep == nil {
			keep = make(imap.CapSet)
		}
		keep[c] = struct{}{}
	}

	// Apply capability filtering based on client identification and/or TLS fingerprint
	disabledCaps, kept := s.server.filterCapabilitiesForClientExcept(caps, s.clientID, s.ja4Fingerprint, keep)
	if len(kept) > 0 {
		slices.Sort(kept)
		kept = slices.Compact(kept)
	}

	// Atomic store - safe for concurrent access
	s.sessionCaps.Store(caps)

	if len(kept) > 0 {
		s.InfoLog("capability filters partly applied, the connection has enabled what they disable", "kept", kept)
	}
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

// enabledCaps returns the extensions this connection has enabled: those the
// client named in ENABLE, CONDSTORE once the client has issued any CONDSTORE
// enabling command (SELECT (CONDSTORE), FETCH MODSEQ, ...: RFC 7162 §3.1), and
// IMAP4rev2 on a server that does not offer IMAP4rev1, where go-imap serves
// every connection IMAP4rev2.
func (s *IMAPSession) enabledCaps() imap.CapSet {
	if s.conn == nil {
		return nil
	}
	enabled := s.conn.EnabledCaps()
	if s.conn.IsIMAP4rev2() {
		enabled[imap.CapIMAP4rev2] = struct{}{}
	}
	if s.conn.CondStoreEnabled() {
		enabled[imap.CapCondStore] = struct{}{}
	}
	return enabled
}

// pinnedContext returns ctx marked to read from the master DB when the session is
// pinned to it (a write earlier in the session), so the command reads its own
// session's writes rather than a lagging read replica.
func (s *IMAPSession) pinnedContext(ctx context.Context) context.Context {
	if s.useMasterDB.Load() {
		return context.WithValue(ctx, consts.UseMasterDBKey, true)
	}
	return ctx
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
		// context.Canceled is handled by the early-return at the top of this
		// method (a client disconnect is suppressed, not tracked), so it never
		// reaches this switch.
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

	// A second call must not count the session out again.
	if s.closed {
		return nil
	}
	s.closed = true

	// Untrack connection from active connections
	if s.conn != nil {
		s.server.untrackConnection(s.conn)
	}

	// Drop the NOTIFY watch (the pump goroutine is already stopped by the
	// library before the session is closed).
	s.notifyMutex.Lock()
	s.notifyWatch = nil
	s.notifyMutex.Unlock()

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

	// Count the session out of Close's drain
	s.server.sessions.Done()

	return nil
}

func (s *IMAPSession) clearSelectedMailboxStateLocked() {
	if s.sessionTracker != nil {
		s.sessionTracker.Close()
	}
	s.releaseBodySectionCache()
	s.selectedMailbox = nil
	s.selectedReadOnly.Store(false)
	s.selectedExamined.Store(false)
	s.mailboxTracker = nil
	s.sessionTracker = nil
	s.currentHighestModSeq.Store(0)
	s.reportedHighestModSeq.Store(0)
	s.reportedModSeqGap.Store(false)
	s.queuedFlagUpdates.Store(false)
	s.recentUnsent.Store(false)
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

// ResetSearchRes empties the saved "$" result (imapserver.SessionSearchRes).
// go-imap calls it when it answers a SAVE search NO itself, before calling
// Search or MultiSearch, as for an unsupported CHARSET (RFC 5182 §2.1).
func (s *IMAPSession) ResetSearchRes() {
	s.setSavedSearchResult(nil)
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

// decodeNumSetLocked translates a command's message set into the server view the
// database numbers (seqView.decode). The caller holds s.mutex (a read lock will do)
// and seqViewMu.
func (s *IMAPSession) decodeNumSetLocked(view seqView, numSet imap.NumSet) imap.NumSet {
	// RFC 5182 / RFC 9051 §6.4.4.1: resolve the "$" saved-search-result marker to
	// this session's saved UID set (empty if nothing has been saved). The marker
	// is always a UIDSet, so the result bypasses sequence-number translation.
	if imap.IsSearchRes(numSet) {
		return s.savedSearchResultLocked()
	}
	if seqSet, ok := numSet.(imap.SeqSet); ok && view.tracker != nil {
		return view.decode(seqSet)
	}
	return numSet
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

// registerConnection takes a slot for the logging-in account in the connection
// tracker. It runs before s.IMAPUser / s.Session.User are set so a rejected
// login leaves the session unauthenticated.
func (s *IMAPSession) registerConnection(accountID int64, email string) error {
	if s.server.connTracker != nil {
		// Use configured database query timeout for connection tracking (database INSERT)
		queryTimeout := s.server.rdb.GetQueryTimeout()
		ctx, cancel := context.WithTimeout(s.ctx, queryTimeout)
		defer cancel()

		// The client's address, not the TCP peer: behind a proxy the peer is
		// the proxy for every client. RemoteIP already holds the address from
		// the PROXY header or a trusted proxy's ID forwarding.
		clientAddr := s.RemoteIP

		if err := s.server.connTracker.RegisterConnection(ctx, accountID, email, "IMAP", clientAddr); err != nil {
			s.InfoLog("connection registration rejected", "address", email, "error", err)
			return err
		}
		s.trackedClientAddr = clientAddr
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

		if err := s.server.connTracker.UnregisterConnection(ctx, s.AccountID(), "IMAP", s.trackedClientAddr); err != nil {
			s.InfoLog("failed to unregister connection", "error", err)
		}
	}
}

// startTerminationPoller starts a goroutine that waits for kick notifications
func (s *IMAPSession) startTerminationPoller() {
	if s.server.connTracker == nil || s.IMAPUser == nil {
		return
	}

	// Capture everything the poller goroutine needs up front: Close() nils
	// s.IMAPUser/s.User under s.mutex, and the poller runs unsynchronized
	// with teardown — reading them later (s.AccountID(), s.InfoLog's user
	// fields) races with those writes. s.conn is set once at construction,
	// so the captured net.Conn is safe to close from here.
	accountID := s.AccountID()
	user := s.FullAddress()
	sessionID := s.Id
	netConn := s.conn.NetConn()

	// Register session for kick notifications and get a channel that closes on kick
	kickChan := s.server.connTracker.RegisterSession(accountID)

	go func() {
		// Unregister when done
		defer s.server.connTracker.UnregisterSession(accountID, kickChan)

		select {
		case <-kickChan:
			// Kick notification received - close connection. Log with the
			// captured identity; s.InfoLog would re-read session fields that
			// a concurrent Close may be nilling.
			logger.Info("connection kicked, disconnecting user",
				"protocol", s.Protocol, "user", user, "account_id", accountID, "session", sessionID)
			netConn.Close()
		case <-s.ctx.Done():
			// Session ended normally
		}
	}()
}
