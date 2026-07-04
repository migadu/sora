package pop3

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/storage"

	"github.com/migadu/go-pop3/pop3"
	"github.com/migadu/go-pop3/pop3server"
)

const Pop3MaxErrorsAllowed = 3                  // Maximum number of errors tolerated before the connection is terminated
const Pop3ErrorDelay = 3 * time.Second          // Wait for this many seconds before allowing another command
const Pop3DefaultIdleTimeout = 10 * time.Minute // RFC 1939 §3: auto-logout timer MUST be at least 10 minutes
const Pop3MaxLineLength = 1024                  // RFC 1939 §3: commands and responses limited to 512 octets (use 1024 for safety)

// Compile-time checks: the library discovers optional capabilities (SASL, LANG,
// UTF8) via type assertions, so a signature drift would silently drop the
// capability instead of failing the build.
var (
	_ pop3server.Session     = (*POP3Session)(nil)
	_ pop3server.SessionSASL = (*POP3Session)(nil)
	_ pop3server.SessionLang = (*POP3Session)(nil)
	_ pop3server.SessionUTF8 = (*POP3Session)(nil)
)

type POP3Session struct {
	server.Session
	server           *POP3Server
	conn             net.Conn     // Connection to the client
	mutex            sync.RWMutex // Mutex for protecting session state
	mutexHelper      *server.MutexTimeoutHelper
	authenticated    atomic.Bool        // Flag to indicate if the user has been authenticated
	messages         []db.POP3Message   // Lean message list for the mailbox, cached for the session (RFC 1939 stable numbering)
	messagesMemBytes int64              // Bytes charged to memTracker for the cached messages slice (guarded by mutex)
	deleted          map[int]bool       // Map of message IDs marked for deletion
	inboxMailboxID   int64              // POP3 suppots only INBOX
	ctx              context.Context    // Context for this session
	cancel           context.CancelFunc // Function to cancel the session's context
	errorsCount      int                // Number of errors encountered during the session
	language         string             // Current language for responses (default "en")
	utf8Mode         atomic.Bool        // UTF8 mode enabled for this session
	xclientApplied   bool               // Whether a trusted XCLIENT has already been accepted (pre-auth, at most once)
	releaseConn      func()             // Function to release connection from limiter
	useMasterDB      atomic.Bool        // Pin session to master DB after a write to ensure consistency
	startTime        time.Time
	memTracker       *server.SessionMemoryTracker // Memory usage tracker for this session

	// Session statistics for summary logging
	messagesRetrieved int // Messages retrieved with RETR
	messagesDeleted   int // Messages marked for deletion with DELE
	messagesExpunged  int // Messages actually expunged on QUIT
}

// Wire errors returned to clients. Using *pop3server.Error keeps the POP3
// response code explicit and guarantees no internal error text (DB drivers,
// S3 keys) reaches the wire; StrictSessionErrors masks anything else.
var (
	errNoSuchMessage   = &pop3server.Error{Message: "No such message"}
	errMessageDeleted  = &pop3server.Error{Message: "Message already deleted"}
	errMsgNotAvailable = &pop3server.Error{Message: "Message not available"}
	errEmptyBody       = &pop3server.Error{Message: "Message body is empty"}
	errAuthFailed      = &pop3server.Error{Code: "AUTH", Message: "Authentication failed"}
	errTempUnavailable = &pop3server.Error{Code: "SYS/TEMP", Message: "Service temporarily unavailable, please try again later"}
	errBodyRetryLater  = &pop3server.Error{Code: "SYS/TEMP", Message: "Message temporarily unavailable, please try again later"}
	errServerBusy      = &pop3server.Error{Code: "SYS/TEMP", Message: "Server busy, please try again"}
	errMailboxTooBig   = &pop3server.Error{Code: "SYS/TEMP", Message: "Mailbox too large to open in this session"}
	errBodyTooBig      = &pop3server.Error{Code: "SYS/TEMP", Message: "Message too large to retrieve in this session"}
)

// pop3AuthError builds an [AUTH]-coded response error (RFC 3206).
func pop3AuthError(msg string) *pop3server.Error {
	return &pop3server.Error{Code: "AUTH", Message: msg}
}

// errPOP3MailboxTooLarge indicates the INBOX listing would exceed the session
// memory limit. POP3 has no pagination (RFC 1939), so rather than silently
// truncate the mailbox the server refuses the listing; the operator can raise
// [limits] session_memory_limit (or set it to 0 for unlimited) to allow very
// large mailboxes.
var errPOP3MailboxTooLarge = errors.New("mailbox too large for session memory limit")

// setMessagesLocked stores the freshly loaded list as the session's cached
// messages and charges it against the per-session memory tracker, so the cached
// slice counts toward the same [limits] session_memory_limit as fetched message
// bodies. It must be called with the write lock held. It releases any prior
// charge first (idempotent across reloads) and returns errPOP3MailboxTooLarge
// without storing anything if the listing would exceed the limit.
func (s *POP3Session) setMessagesLocked(messages []db.POP3Message) error {
	var charged int64
	for i := range messages {
		charged += messages[i].ApproxMemSize()
	}
	if s.memTracker != nil {
		if s.messagesMemBytes > 0 {
			s.memTracker.Free(s.messagesMemBytes)
			s.messagesMemBytes = 0
		}
		if err := s.memTracker.Allocate(charged); err != nil {
			metrics.SessionMemoryLimitExceeded.WithLabelValues("pop3", s.server.name, s.server.hostname).Inc()
			s.WarnLog("INBOX listing exceeds session memory limit",
				"messages", len(messages), "bytes", charged, "limit", s.memTracker.MaxAllowed())
			return errPOP3MailboxTooLarge
		}
		s.messagesMemBytes = charged
	}
	s.messages = messages
	return nil
}

// pop3LoadLimit returns the maximum number of message rows to fetch when loading
// the mailbox, so the transient slice is bounded by the session memory budget
// BEFORE setMessagesLocked charges it. Using the per-message floor
// (db.POP3MessageMinMemSize) means a mailbox with more rows than this cannot fit
// even in the best case, so fetching only this many (setMessagesLocked then
// rejects) avoids materializing a multi-GB slice for a huge mailbox. Returns 0
// (unlimited) when no memory limit is configured. The +1 ensures a mailbox sitting
// exactly at the boundary is still fetched and rejected rather than silently
// truncated.
func (s *POP3Session) pop3LoadLimit() int {
	if s.memTracker == nil {
		return 0
	}
	max := s.memTracker.MaxAllowed()
	if max <= 0 {
		return 0 // unlimited
	}
	return int(max/db.POP3MessageMinMemSize) + 1
}

func (s *POP3Session) loadMessagesIfNeeded(ctx context.Context) error {
	s.mutex.RLock()
	needsLoading := (s.messages == nil)
	mailboxID := s.inboxMailboxID
	s.mutex.RUnlock()

	if !needsLoading {
		return nil
	}

	readCtx := ctx
	if s.useMasterDB.Load() {
		readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	}

	messages, err := s.server.rdb.ListMessagesForPOP3WithRetry(readCtx, mailboxID, s.pop3LoadLimit())
	if err != nil {
		s.WarnLog("failed to load INBOX listing", "mailbox_id", mailboxID, "error", err)
		return errTempUnavailable
	}

	acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout(ctx)
	if !acquired {
		return errServerBusy
	}
	defer release()

	// Double check under write lock
	if s.messages != nil {
		return nil
	}

	if err := s.setMessagesLocked(messages); err != nil {
		if errors.Is(err, errPOP3MailboxTooLarge) {
			return errMailboxTooBig
		}
		return errTempUnavailable
	}
	return nil
}

func (s *POP3Session) authenticateUser(ctx context.Context, identity, username, password string, isSASL bool) (int64, error) {
	// Apply progressive authentication delay BEFORE any other checks
	remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
	delayType := "POP3-PASS"
	if isSASL {
		delayType = "POP3-SASL"
	}
	if err := server.ApplyAuthenticationDelay(ctx, s.server.authLimiter, remoteAddr, delayType); err != nil {
		if errors.Is(err, server.ErrDelayQueueFull) {
			s.InfoLog("delay queue full, rejecting connection", "username", username)
			return 0, &pop3server.Error{Code: "IN-USE", Message: "Too many concurrent authentication attempts. Please try again later."}
		}
		return 0, err
	}

	netConn := s.conn
	var proxyInfo *server.ProxyProtocolInfo
	if s.ProxyIP != "" {
		proxyInfo = &server.ProxyProtocolInfo{
			SrcIP: s.RemoteIP,
		}
	}

	// Check authentication rate limiting after delay. Keyed on the raw submitted
	// username: a master SASL username is an opaque credential that need not be
	// an email address, so this runs before any address parsing.
	if s.server.authLimiter != nil {
		if err := s.server.authLimiter.CanAttemptAuthWithProxy(ctx, netConn, proxyInfo, username); err != nil {
			var rateLimitErr *server.RateLimitError
			if errors.As(err, &rateLimitErr) {
				s.InfoLog("rate limit exceeded",
					"username", username,
					"reason", rateLimitErr.Reason,
					"failure_count", rateLimitErr.FailureCount,
					"blocked_until", rateLimitErr.BlockedUntil.Format(time.RFC3339))
			} else {
				s.DebugLog("rate limited", "error", err)
			}
			metrics.AuthenticationAttempts.WithLabelValues("pop3", s.server.name, s.server.hostname, "rate_limited").Inc()
			return 0, errAuthFailed
		}
	}

	authSuccess := false
	masterAuthUsed := false
	var accountID int64
	var userAddress *server.Address

	// Master SASL password authentication. Checked on the RAW username before any
	// address parsing: the master SASL username (e.g. "proxyuser") is not
	// necessarily an email address; only the impersonation target must parse.
	if len(s.server.masterSASLUsername) > 0 && len(s.server.masterSASLPassword) > 0 &&
		checkMasterCredential(username, s.server.masterSASLUsername) && checkMasterCredential(password, s.server.masterSASLPassword) {
		if !s.server.masterSASLGate.Allowed(netConn.RemoteAddr()) {
			s.WarnLog("master SASL credentials valid but source not in master_sasl_allowed_networks; rejecting", "peer", server.GetAddrString(netConn.RemoteAddr()))
			return 0, errAuthFailed
		}
		if identity == "" {
			return 0, pop3AuthError("Master SASL login requires an authorization identity.")
		}
		s.DebugLog("master sasl password authentication successful", "base_address", identity)

		targetAddr, err := server.NewAddress(identity)
		if err != nil {
			return 0, pop3AuthError("Invalid impersonation target user format")
		}

		accountID, err = s.server.rdb.GetActiveAccountIDByAddressWithRetry(ctx, targetAddr.BaseAddress())
		if err != nil {
			s.DebugLog("failed to get account id for master user", "base_address", targetAddr.BaseAddress(), "error", err)
			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, targetAddr.BaseAddress(), false)
			}
			return 0, errAuthFailed
		}
		authSuccess = true
		masterAuthUsed = true
		// The session belongs to the impersonated account, not the master credential.
		userAddress = &targetAddr
	}

	if !authSuccess {
		newUserAddress, err := server.NewAddress(username)
		if err != nil {
			s.DebugLog("invalid username format", "error", err)
			return 0, pop3AuthError("Invalid username format")
		}
		userAddress = &newUserAddress

		// Master username authentication: user@domain.com@MASTER_USERNAME
		if len(s.server.masterUsername) > 0 && userAddress.HasSuffix() && checkMasterCredential(userAddress.Suffix(), s.server.masterUsername) {
			if len(s.server.masterPassword) > 0 && checkMasterCredential(password, s.server.masterPassword) {
				if !s.server.masterSASLGate.Allowed(netConn.RemoteAddr()) {
					s.WarnLog("master username credentials valid but source not in master_sasl_allowed_networks; rejecting", "peer", server.GetAddrString(netConn.RemoteAddr()))
					if s.server.authLimiter != nil {
						s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, userAddress.BaseAddress(), false)
					}
					return 0, errAuthFailed
				}
				s.DebugLog("master username authentication successful", "base_address", userAddress.BaseAddress(), "master_username", userAddress.Suffix())

				targetUser := identity
				if targetUser == "" {
					targetUser = userAddress.BaseAddress()
				}
				targetAddr, err := server.NewAddress(targetUser)
				if err != nil {
					return 0, pop3AuthError("Invalid impersonation target user format")
				}

				accountID, err = s.server.rdb.GetActiveAccountIDByAddressWithRetry(ctx, targetAddr.BaseAddress())
				if err != nil {
					s.DebugLog("failed to get account id for user", "base_address", targetAddr.BaseAddress(), "error", err)
					if s.server.authLimiter != nil {
						s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, targetAddr.BaseAddress(), false)
					}
					return 0, errAuthFailed
				}
				authSuccess = true
				masterAuthUsed = true
				userAddress = &targetAddr
			} else {
				metrics.AuthenticationAttempts.WithLabelValues("pop3", s.server.name, s.server.hostname, "failure").Inc()
				if s.server.authLimiter != nil {
					s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, userAddress.BaseAddress(), false)
				}
				return 0, pop3AuthError("Invalid master credentials")
			}
		}
	}

	// Regular authentication
	if !authSuccess {
		if identity != "" && identity != username {
			return 0, pop3AuthError("Proxy authentication requires master credentials")
		}

		var err error
		accountID, err = s.server.Authenticate(ctx, userAddress.BaseAddress(), password)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				s.InfoLog("authentication cancelled due to server shutdown")
				return 0, errTempUnavailable
			}

			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, userAddress.FullAddress(), false)
			}
			metrics.AuthenticationAttempts.WithLabelValues("pop3", s.server.name, s.server.hostname, "failure").Inc()
			return 0, errAuthFailed
		}
		authSuccess = true
	}

	// Record successful attempt
	if s.server.authLimiter != nil {
		s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, userAddress.FullAddress(), true)
	}

	// Ensure default mailboxes exist
	if err := s.server.rdb.CreateDefaultMailboxesWithRetry(ctx, accountID); err != nil {
		s.DebugLog("error creating default mailboxes", "error", err)
		return 0, errTempUnavailable
	}

	// Get INBOX mailbox ID
	readCtx := context.WithValue(ctx, consts.UseMasterDBKey, true)
	inboxMailboxID, err := s.server.rdb.GetMailboxByNameWithRetry(readCtx, accountID, consts.MailboxInbox)
	if err != nil {
		s.DebugLog("error getting inbox", "error", err)
		return 0, errTempUnavailable
	}

	// Setup session state
	s.mutex.Lock()
	s.inboxMailboxID = inboxMailboxID.ID
	s.User = server.NewUser(*userAddress, accountID)
	s.deleted = make(map[int]bool)
	s.useMasterDB.Store(true)
	s.mutex.Unlock()

	s.server.authenticatedConnections.Add(1)

	if masterAuthUsed {
		s.InfoLog("authentication successful", "address", userAddress.BaseAddress(), "account_id", accountID, "cached", false, "method", "master")
	}

	metrics.AuthenticatedConnectionsCurrent.WithLabelValues("pop3", s.server.name, s.server.hostname).Inc()
	s.authenticated.Store(true)

	// Register connection
	s.registerConnection(userAddress.FullAddress())
	s.startTerminationPoller()

	return accountID, nil
}

func (s *POP3Session) Login(ctx context.Context, username, password string) error {
	_, err := s.authenticateUser(ctx, "", username, password, false)
	return err
}

func (s *POP3Session) AuthenticatePlain(ctx context.Context, identity, username, password string) error {
	_, err := s.authenticateUser(ctx, identity, username, password, true)
	return err
}

func (s *POP3Session) AuthenticateMechanisms() []string {
	return []string{"PLAIN"}
}

func (s *POP3Session) Stat(ctx context.Context) (int, int64, error) {
	if err := s.loadMessagesIfNeeded(ctx); err != nil {
		return 0, 0, err
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	count, size := computeMaildropStats(s.messages, s.deleted)
	return count, size, nil
}

func (s *POP3Session) List(ctx context.Context, msg int) ([]pop3.MessageInfo, error) {
	if err := s.loadMessagesIfNeeded(ctx); err != nil {
		return nil, err
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if msg > 0 {
		if msg > len(s.messages) || s.deleted[msg-1] {
			return nil, errNoSuchMessage
		}
		return []pop3.MessageInfo{
			{Num: msg, Size: int64(s.messages[msg-1].Size)},
		}, nil
	}

	var infos []pop3.MessageInfo
	for i, m := range s.messages {
		if !s.deleted[i] {
			infos = append(infos, pop3.MessageInfo{
				Num:  i + 1,
				Size: int64(m.Size),
			})
		}
	}
	return infos, nil
}

func (s *POP3Session) Uidl(ctx context.Context, msg int) ([]pop3.MessageUidl, error) {
	if err := s.loadMessagesIfNeeded(ctx); err != nil {
		return nil, err
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if msg > 0 {
		if msg > len(s.messages) || s.deleted[msg-1] {
			return nil, errNoSuchMessage
		}
		return []pop3.MessageUidl{
			{Num: msg, UniqueID: strconv.FormatInt(int64(s.messages[msg-1].UID), 10)},
		}, nil
	}

	var uids []pop3.MessageUidl
	for i, m := range s.messages {
		if !s.deleted[i] {
			uids = append(uids, pop3.MessageUidl{
				Num:      i + 1,
				UniqueID: strconv.FormatInt(int64(m.UID), 10),
			})
		}
	}
	return uids, nil
}

func (s *POP3Session) Retr(ctx context.Context, msgNum int) (io.ReadCloser, error) {
	if err := s.loadMessagesIfNeeded(ctx); err != nil {
		return nil, err
	}

	s.mutex.RLock()
	if msgNum > len(s.messages) || s.deleted[msgNum-1] {
		s.mutex.RUnlock()
		return nil, errNoSuchMessage
	}
	msg := s.messages[msgNum-1]
	s.mutex.RUnlock()

	if msg.UID == 0 {
		return nil, errNoSuchMessage
	}

	s.DebugLog("fetching message body", "uid", msg.UID)
	retrieveStart := time.Now()
	bodyData, err := s.getMessageBody(&msg)
	if err != nil {
		if err == consts.ErrMessageNotAvailable {
			return nil, errMsgNotAvailable
		} else if errors.Is(err, errBodyTransientlyUnavailable) {
			return nil, errBodyRetryLater
		}
		var perr *pop3server.Error
		if errors.As(err, &perr) {
			return nil, perr
		}
		return nil, errTempUnavailable
	}

	s.DebugLog("retrieved message body", "uid", msg.UID)
	if len(bodyData) == 0 {
		s.freeBodyMem(int64(len(bodyData)))
		return nil, errEmptyBody
	}

	// Byte metrics use the announced (CRLF-normalized) octet count — the bytes
	// the client reconstructs — rather than the stored msg.Size, which
	// undercounts for bare-LF bodies. Dot-stuffing bytes and the .CRLF
	// terminator (added by the library) are deliberately excluded.
	announcedOctets := crlfNormalizedLen(bodyData)
	metrics.MessageThroughput.WithLabelValues("pop3", "retrieved", "success").Inc()
	metrics.BytesThroughput.WithLabelValues("pop3", "out").Add(float64(announcedOctets))
	metrics.CriticalOperationDuration.WithLabelValues("pop3_retrieve").Observe(time.Since(retrieveStart).Seconds())
	if s.User != nil {
		metrics.TrackDomainCommand("pop3", s.Domain(), "RETR")
		metrics.TrackUserActivity("pop3", s.FullAddress(), "command", 1)
		metrics.TrackDomainBytes("pop3", s.Domain(), "out", int64(announcedOctets))
		metrics.TrackDomainMessage("pop3", s.Domain(), "fetched")
	}

	s.messagesRetrieved++
	body := &freeOnCloseBody{
		Reader: bytes.NewReader(bodyData),
		free:   func() { s.freeBodyMem(int64(len(bodyData))) },
	}
	return pop3server.SizedBody(body, int64(announcedOctets)), nil
}

// freeOnCloseBody releases the session memory charged for a fetched body once
// the library has finished streaming it to the client. Without this, every
// RETR/TOP would accumulate against the session memory budget until QUIT.
type freeOnCloseBody struct {
	io.Reader
	free func()
	once sync.Once
}

func (b *freeOnCloseBody) Close() error {
	b.once.Do(b.free)
	return nil
}

// freeBodyMem returns a body-sized allocation to the session memory tracker.
func (s *POP3Session) freeBodyMem(n int64) {
	if s.memTracker != nil && n > 0 {
		s.memTracker.Free(n)
	}
}

func (s *POP3Session) Top(ctx context.Context, msgNum int, lines int) (io.ReadCloser, error) {
	if err := s.loadMessagesIfNeeded(ctx); err != nil {
		return nil, err
	}

	s.mutex.RLock()
	if msgNum > len(s.messages) || s.deleted[msgNum-1] {
		s.mutex.RUnlock()
		return nil, errNoSuchMessage
	}
	msg := s.messages[msgNum-1]
	s.mutex.RUnlock()

	if msg.UID == 0 {
		return nil, errNoSuchMessage
	}

	bodyData, err := s.getMessageBody(&msg)
	if err != nil {
		if err == consts.ErrMessageNotAvailable {
			return nil, errMsgNotAvailable
		} else if errors.Is(err, errBodyTransientlyUnavailable) {
			return nil, errBodyRetryLater
		}
		var perr *pop3server.Error
		if errors.As(err, &perr) {
			return nil, perr
		}
		return nil, errTempUnavailable
	}

	truncated := truncateToTop(bodyData, lines)
	// The memory tracker charge covers the full body fetched by getMessageBody,
	// so the release on Close must match it, not the truncated slice.
	return &freeOnCloseBody{
		Reader: bytes.NewReader(truncated),
		free:   func() { s.freeBodyMem(int64(len(bodyData))) },
	}, nil
}

func truncateToTop(bodyData []byte, lines int) []byte {
	messageStr := string(bodyData)
	messageStr = strings.ReplaceAll(messageStr, "\r\n", "\n")

	headerEndIndex := strings.Index(messageStr, "\n\n")
	if headerEndIndex == -1 {
		return []byte(messageStr)
	}

	headers := messageStr[:headerEndIndex]
	if lines == 0 {
		return []byte(headers + "\n\n")
	}

	bodyStart := headerEndIndex + 2
	if bodyStart >= len(messageStr) {
		return []byte(headers + "\n\n")
	}

	bodyPart := messageStr[bodyStart:]
	bodyLines := strings.Split(bodyPart, "\n")

	numLines := lines
	if numLines > len(bodyLines) {
		numLines = len(bodyLines)
	}

	selectedLines := bodyLines[:numLines]
	bodySnippet := strings.Join(selectedLines, "\n")

	return []byte(headers + "\n\n" + bodySnippet)
}

func (s *POP3Session) Dele(ctx context.Context, msg int) error {
	if err := s.loadMessagesIfNeeded(ctx); err != nil {
		return err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if msg < 1 || msg > len(s.messages) {
		return errNoSuchMessage
	}
	if s.deleted[msg-1] {
		return errMessageDeleted
	}

	s.deleted[msg-1] = true
	s.messagesDeleted++
	metrics.MessageThroughput.WithLabelValues("pop3", "deleted", "success").Inc()
	return nil
}

func (s *POP3Session) Rset(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for k := range s.deleted {
		delete(s.deleted, k)
	}
	s.messagesDeleted = 0
	return nil
}

func (s *POP3Session) Noop(ctx context.Context) error {
	return nil
}

func (s *POP3Session) Quit(ctx context.Context) (int, error) {
	commitOK := true

	s.mutex.RLock()
	mailboxID := s.inboxMailboxID
	var messagesToExpunge []db.POP3Message
	for i, deleted := range s.deleted {
		if deleted && i < len(s.messages) {
			messagesToExpunge = append(messagesToExpunge, s.messages[i])
		}
	}
	s.mutex.RUnlock()

	var expungeUIDs []imap.UID
	for _, msg := range messagesToExpunge {
		s.DebugLog("will expunge message", "uid", msg.UID)
		expungeUIDs = append(expungeUIDs, msg.UID)
	}

	if len(expungeUIDs) > 0 {
		s.DebugLog("expunging messages", "count", len(expungeUIDs), "mailbox_id", mailboxID, "uids", expungeUIDs)
		_, err := s.server.rdb.ExpungeMessageUIDsWithRetry(ctx, mailboxID, expungeUIDs...)
		if err != nil {
			commitOK = false
			s.WarnLog("error expunging messages at QUIT", "mailbox_id", mailboxID, "error", err)
		} else {
			s.DebugLog("successfully expunged messages", "count", len(expungeUIDs), "mailbox_id", mailboxID)
			s.messagesExpunged = len(expungeUIDs)
		}
	}

	if !commitOK {
		return 0, &pop3server.Error{Code: "SYS/TEMP", Message: "some messages could not be removed; maildrop unchanged"}
	}

	return s.messagesExpunged, nil
}

func (s *POP3Session) SetLanguage(ctx context.Context, lang string) (string, error) {
	langTag := strings.ToLower(lang)
	if langTag != "en" && langTag != "*" && langTag != "i-default" {
		return "", &pop3server.Error{Message: "Unsupported language"}
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if langTag == "i-default" {
		s.language = "i-default"
	} else {
		s.language = "en"
	}
	return s.language, nil
}

func (s *POP3Session) ListLanguages(ctx context.Context) ([]pop3server.LanguageInfo, error) {
	return []pop3server.LanguageInfo{
		{Tag: "en", Description: "English"},
		{Tag: "i-default", Description: "Default"},
	}, nil
}

func (s *POP3Session) EnableUTF8(ctx context.Context) error {
	s.utf8Mode.Store(true)
	s.DebugLog("utf8 mode enabled")
	return nil
}

func (s *POP3Session) closeWithoutLock() error {
	duration := time.Since(s.startTime)
	metrics.ConnectionDuration.WithLabelValues("pop3", s.server.name, s.server.hostname).Observe(duration.Seconds())

	// Log and record peak memory usage
	if s.memTracker != nil {
		peak := s.memTracker.Peak()
		metrics.SessionMemoryPeakBytes.WithLabelValues("pop3", s.server.name, s.server.hostname).Observe(float64(peak))
		if peak > 0 {
			s.DebugLog("session memory peak", "peak", server.FormatBytes(peak))
		}
	}

	// Log session summary with statistics (similar to Dovecot)
	if s.messagesRetrieved > 0 || s.messagesDeleted > 0 || s.messagesExpunged > 0 {
		s.InfoLog("session summary",
			"duration", fmt.Sprintf("%.1fs", duration.Seconds()),
			"retrieved", s.messagesRetrieved,
			"deleted", s.messagesDeleted,
			"expunged", s.messagesExpunged)
	}

	totalCount := s.server.totalConnections.Add(-1)
	var authCount int64 = 0

	// Prometheus metrics - connection closed
	metrics.ConnectionsCurrent.WithLabelValues("pop3", s.server.name, s.server.hostname).Dec()

	if s.conn != nil {
		s.conn.Close()
	}

	// Remove session from active tracking
	s.server.removeSession(s)

	// Release connection from limiter
	if s.releaseConn != nil {
		s.releaseConn()
		s.releaseConn = nil // Prevent double release
	}

	if s.User != nil {
		if s.authenticated.Load() {
			authCount = s.server.authenticatedConnections.Add(-1)
			metrics.AuthenticatedConnectionsCurrent.WithLabelValues("pop3", s.server.name, s.server.hostname).Dec()

			// Unregister connection from tracker
			s.unregisterConnection()
		} else {
			authCount = s.server.authenticatedConnections.Load()
		}
		s.InfoLog("closed", "total_connections", totalCount, "authenticated_connections", authCount)

		// Clean up session state. Release the memory charged for the cached message
		// list back to the session tracker before dropping the slice.
		s.User = nil
		s.Id = ""
		if s.memTracker != nil && s.messagesMemBytes > 0 {
			s.memTracker.Free(s.messagesMemBytes)
		}
		s.messagesMemBytes = 0
		s.messages = nil
		s.deleted = nil
		s.authenticated.Store(false)

		if s.cancel != nil { // Ensure session cancel is called if not already
			s.cancel()
		}
	} else {
		authCount = s.server.authenticatedConnections.Load()
		s.DebugLog("closed unauthenticated connection", "total_connections", totalCount, "authenticated_connections", authCount)
	}

	return nil
}

func (s *POP3Session) Close() error {
	acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout(s.ctx)
	if !acquired {
		s.WarnLog("failed to acquire write lock within timeout")
		// Still close the connection even if we can't acquire the lock
		return s.closeWithoutLock()
	}
	defer release()
	return s.closeWithoutLock()
}

// errBodyTransientlyUnavailable marks a message body that exists (or will shortly) but
// cannot be retrieved from this node right now. Two causes feed it, both transient:
//   - not yet uploaded: staged for upload, not on local disk here and not in S3 yet
//     (the upload worker will land it shortly); see bodyUploadStillPending.
//   - S3 unavailable: the message is uploaded but S3 is unreachable (network/timeout/
//     5xx/circuit-open) — distinct from a 404/NoSuchKey, which is permanent loss.
//
// RETR/TOP answer it with -ERR [SYS/TEMP] ... please try again later so the client
// retries (and does not DELE), rather than -ERR Message not available which reads as a
// permanent failure. The wrapping error text carries the specific cause for logging.
var errBodyTransientlyUnavailable = errors.New("message body temporarily unavailable")

// pop3BodyFetchRetry* tune the bounded retry of the S3 read on the not-yet-uploaded path.
// They absorb the read-before-write race where the background S3 PUT lands shortly after
// the fetch (e.g. a cross-node delivery still uploading). The wait is only ever spent
// when an upload is still pending (loadMessageBody gates on bodyUploadStillPending), so a
// body that is never coming is not waited on; and because a transient result aborts the
// connection/session command, at most one message per command pays it. The window is generous:
// ~(pop3BodyFetchRetryAttempts-1) * pop3BodyFetchRetryDelay ≈ 1s.
const (
	pop3BodyFetchRetryAttempts = 3
	pop3BodyFetchRetryDelay    = 500 * time.Millisecond
)

func (s *POP3Session) getMessageBody(msg *db.POP3Message) ([]byte, error) {
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted, aborting message body fetch")
		return nil, fmt.Errorf("request aborted")
	}

	// Pre-read guard: refuse a body that can't fit the session budget BEFORE pulling it
	// into memory. The post-read Allocate() below can only detect the overrun once the
	// body is already resident — too late to prevent the OOM. msg.Size is the stored
	// metadata size, so this bounds the single allocation. (security-audit M13)
	if s.memTracker != nil && msg.Size > 0 && !s.memTracker.CanAllocate(int64(msg.Size)) {
		metrics.SessionMemoryLimitExceeded.WithLabelValues("pop3", s.server.name, s.server.hostname).Inc()
		s.WarnLog("session memory limit exceeded", "uid", msg.UID, "size", msg.Size)
		return nil, errBodyTooBig
	}

	data, err := s.loadMessageBody(msg)
	if err != nil {
		return nil, err
	}

	// Single accounting point for every source in loadMessageBody (cache, S3, disk).
	if s.memTracker != nil {
		if allocErr := s.memTracker.Allocate(int64(len(data))); allocErr != nil {
			metrics.SessionMemoryLimitExceeded.WithLabelValues("pop3", s.server.name, s.server.hostname).Inc()
			s.WarnLog("session memory limit exceeded", "uid", msg.UID, "size", len(data), "error", allocErr)
			return nil, errBodyTooBig
		}
	}
	return data, nil
}

// loadMessageBody returns the raw message body from the fastest available source.
// Preference order:
//   - uploaded messages:     local cache → S3 → local staging disk (S3 outage)
//   - not-yet-uploaded msgs: local staging disk → S3 (cross-node / late-upload race)
func (s *POP3Session) loadMessageBody(msg *db.POP3Message) ([]byte, error) {
	if msg.IsUploaded {
		// Try cache first (nil-safe: cache is optional and not configured in tests).
		if s.server.cache != nil {
			if cacheData, cacheErr := s.server.cache.Get(msg.ContentHash); cacheErr == nil && cacheData != nil {
				// Validate cached data is not empty
				if len(cacheData) == 0 {
					s.WarnLog("cache contains empty body, falling through to S3", "uid", msg.UID, "content_hash", msg.ContentHash)
				} else {
					s.DebugLog("cache hit", "uid", msg.UID)
					return cacheData, nil
				}
			}
		}

		// Fallback to S3
		s.DebugLog("cache miss - fetching from S3", "uid", msg.UID, "hash", msg.ContentHash)
		data, err := s.fetchBodyFromS3(msg)
		if err != nil {
			// S3 is unavailable — fall back to the local staging file if the uploader
			// still has it. This covers test environments (where S3 is a no-op stub)
			// and transient S3 outages where the upload worker has not yet run.
			if s.server.uploader != nil {
				filePath := s.server.uploader.FilePath(msg.ContentHash, msg.AccountID)
				if diskData, diskErr := os.ReadFile(filePath); diskErr == nil && len(diskData) > 0 {
					s.DebugLog("S3 unavailable, served from local disk", "uid", msg.UID)
					return diskData, nil
				}
			}
			// The message is marked uploaded but S3 could not serve it and the local
			// staging copy is gone. Distinguish a transient S3 outage (network/timeout/
			// 5xx/circuit-open) from a genuinely missing object (404/NoSuchKey): on a
			// transient failure ask the client to retry (RETR/TOP -> -ERR [SYS/TEMP])
			// instead of reporting the message permanently gone. A NoSuchKey maps to
			// -ERR Message not available (the object is permanently lost).
			// Only a genuine S3-reachability failure is transient. fetchBodyFromS3 wraps
			// such failures (network/timeout/5xx/circuit-open) in ErrRetrieveFailed; it
			// also wraps NoSuchKey there, which IsNotFoundError excludes. Permanent
			// conditions (empty/0-byte object, missing S3 key, read error) are NOT
			// ErrRetrieveFailed and must NOT be reported transient, or the client would
			// retry forever instead of getting -ERR Message not available.
			if errors.Is(err, storage.ErrRetrieveFailed) && !resilient.IsNotFoundError(err) {
				return nil, fmt.Errorf("message UID %d: %w (S3 unavailable): %v", msg.UID, errBodyTransientlyUnavailable, err)
			}
			// Permanent. A NoSuchKey on an uploaded message is genuine content loss worth
			// alerting on — logged only here, where the message is marked uploaded (a 404
			// during the not-yet-uploaded race is expected and not logged). RETR/TOP map
			// ErrMessageNotAvailable to -ERR Message not available.
			if resilient.IsNotFoundError(err) {
				s.WarnLog("message marked uploaded but missing from S3 (NoSuchKey)", "uid", msg.UID, "content_hash", msg.ContentHash, "s3_domain", msg.S3Domain, "s3_localpart", msg.S3Localpart)
			}
			return nil, consts.ErrMessageNotAvailable
		}
		return data, nil
	}

	// Not yet uploaded to S3: the body should be in this node's local staging dir.
	if s.server.uploader == nil {
		s.DebugLog("no uploader configured, message not available", "uid", msg.UID)
		return nil, consts.ErrMessageNotAvailable
	}
	s.DebugLog("fetching not yet uploaded message from disk", "uid", msg.UID)
	filePath := s.server.uploader.FilePath(msg.ContentHash, msg.AccountID)
	if data, diskErr := os.ReadFile(filePath); diskErr == nil && len(data) > 0 {
		return data, nil
	}

	// Local staging file is missing or empty. In a multi-backend cluster the body may
	// have been delivered/staged on another node and already uploaded to S3, while this
	// node's in-memory message still reads uploaded=false. Try S3 with the stored key —
	// with a short bounded retry to absorb the read-before-write race where the S3 PUT
	// lands within the same second as this fetch. NoSuchKey fails fast, so each miss is cheap.
	//
	// Decide up front whether the body is still expected to arrive. We only wait-and-retry
	// S3 when it is: there is no point sleeping for a body that is never coming.
	pending := s.bodyUploadStillPending(msg)

	if msg.S3Domain != "" && msg.S3Localpart != "" {
		attempts := 1
		if pending {
			attempts = pop3BodyFetchRetryAttempts
		}
		for attempt := 0; attempt < attempts; attempt++ {
			s3Data, s3Err := s.fetchBodyFromS3(msg)
			if s3Err == nil {
				s.DebugLog("local staging file missing, served from S3", "uid", msg.UID, "attempt", attempt)
				return s3Data, nil
			}
			// Only NoSuchKey ("object hasn't landed yet") benefits from waiting and
			// retrying. Any other error is either a transient outage that GetWithRetry
			// already exhausted its own backoff on (looping would just multiply that
			// latency) or a permanent condition — stop and let classification decide.
			if !resilient.IsNotFoundError(s3Err) {
				break
			}
			if attempt < attempts-1 {
				select {
				case <-time.After(pop3BodyFetchRetryDelay):
				case <-s.ctx.Done():
					return nil, s.ctx.Err()
				}
			}
		}
	}

	// Body still unavailable. Distinguish transient from permanent: if the upload is still
	// pending (or the message has since been marked uploaded), the body is in flight — tell
	// the client to retry (errBodyTransientlyUnavailable -> -ERR [SYS/TEMP] ... try again later, and
	// the client must not DELE). Otherwise the content is genuinely gone, which RETR/TOP map
	// to -ERR Message not available.
	if pending {
		return nil, errBodyTransientlyUnavailable
	}
	s.DebugLog("message body not on disk and not in S3, content unavailable", "uid", msg.UID, "hash", msg.ContentHash)
	return nil, consts.ErrMessageNotAvailable
}

// bodyUploadStillPending reports whether the system still intends to make this body
// available — i.e. a pending_upload record exists, or the message has since been marked
// uploaded (so a retry should find it in S3). It distinguishes the transient
// read-before-upload race from genuine, permanent content loss. On a DB error it returns
// true (conservative: a client retry is safer than reporting the message permanently gone).
func (s *POP3Session) bodyUploadStillPending(msg *db.POP3Message) bool {
	pending, err := s.server.rdb.PendingUploadExistsWithRetry(s.ctx, msg.ContentHash, msg.AccountID)
	if err != nil {
		s.WarnLog("could not check pending-upload status; treating body as transiently unavailable", "uid", msg.UID, "error", err)
		return true
	}
	if pending {
		return true
	}
	uploaded, err := s.server.rdb.IsContentHashUploadedWithRetry(s.ctx, msg.ContentHash, msg.AccountID)
	if err != nil {
		s.WarnLog("could not check uploaded status; treating body as transiently unavailable", "uid", msg.UID, "error", err)
		return true
	}
	return uploaded
}

// fetchBodyFromS3 retrieves a message body from S3 using the key components
// stored on the message record. It validates the payload is non-empty and warms
// the local cache on success.
func (s *POP3Session) fetchBodyFromS3(msg *db.POP3Message) ([]byte, error) {
	if msg.S3Domain == "" || msg.S3Localpart == "" {
		return nil, fmt.Errorf("message UID %d is missing S3 key information", msg.UID)
	}
	s3Key := helpers.NewS3Key(msg.S3Domain, msg.S3Localpart, msg.ContentHash)

	// Guard against a nil-client panic (e.g. test stubs using &storage.S3Storage{})
	// so it becomes an error rather than killing the connection goroutine.
	var reader io.ReadCloser
	var s3GetErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				s3GetErr = fmt.Errorf("S3 get panicked: %v", r)
			}
		}()
		reader, s3GetErr = s.server.s3.GetWithRetry(s.server.appCtx, s3Key)
	}()
	if s3GetErr != nil {
		s.DebugLog("S3 GetWithRetry failed", "uid", msg.UID, "s3_key", s3Key, "error", s3GetErr)
		return nil, fmt.Errorf("message UID %d: %w: %w", msg.UID, storage.ErrRetrieveFailed, s3GetErr)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		s.DebugLog("failed to read S3 response", "uid", msg.UID, "error", err)
		return nil, err
	}
	if len(data) == 0 {
		s.WarnLog("retrieved empty body from S3", "uid", msg.UID, "hash", msg.ContentHash, "s3_key", s3Key)
		return nil, fmt.Errorf("message UID %d (hash: %s): %w", msg.UID, msg.ContentHash, storage.ErrEmptyData)
	}

	s.DebugLog("successfully fetched from S3", "uid", msg.UID, "size", len(data))
	if s.server.cache != nil {
		_ = s.server.cache.Put(msg.ContentHash, data)
	}
	return data, nil
}

// registerConnection registers the connection in the connection tracker
func (s *POP3Session) registerConnection(email string) {
	if s.server.connTracker != nil && s.authenticated.Load() {
		// Use configured database query timeout for connection tracking (database INSERT)
		queryTimeout := s.server.rdb.GetQueryTimeout()
		ctx, cancel := context.WithTimeout(s.ctx, queryTimeout)
		defer cancel()

		clientAddr := server.GetAddrString(s.conn.RemoteAddr())

		if err := s.server.connTracker.RegisterConnection(ctx, s.AccountID(), email, "POP3", clientAddr); err != nil {
			s.InfoLog("rejected connection registration", "error", err)
		}
	}
}

// unregisterConnection removes the connection from the connection tracker
func (s *POP3Session) unregisterConnection() {
	if s.server.connTracker != nil && s.authenticated.Load() {
		// Use configured database query timeout for connection tracking (database DELETE)
		queryTimeout := s.server.rdb.GetQueryTimeout()
		ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
		defer cancel()

		clientAddr := server.GetAddrString(s.conn.RemoteAddr())

		if err := s.server.connTracker.UnregisterConnection(ctx, s.AccountID(), "POP3", clientAddr); err != nil {
			s.DebugLog("failed to unregister connection", "error", err)
		}
	}
}

// startTerminationPoller starts a goroutine that waits for kick notifications
func (s *POP3Session) startTerminationPoller() {
	if s.server.connTracker == nil || !s.authenticated.Load() {
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
			s.conn.Close()
		case <-s.ctx.Done():
			// Session ended normally
		}
	}()
}

func checkMasterCredential(provided string, actual []byte) bool {
	return subtle.ConstantTimeCompare([]byte(provided), actual) == 1
}

// crlfNormalizedLen returns the byte length the body would have once every line
// ending is normalized to CRLF, without allocating. This is the octet count RETR
// announces (RFC 1939 §5) — the exact number of body octets a client reconstructs
// after un-stuffing. It is len(body) plus one for each bare LF (an LF not preceded
// by CR); lone CR bytes are not line terminators in POP3 and are left unchanged.
func crlfNormalizedLen(body []byte) int {
	n := len(body)
	for i := 0; i < len(body); i++ {
		if body[i] == '\n' && (i == 0 || body[i-1] != '\r') {
			n++
		}
	}
	return n
}
