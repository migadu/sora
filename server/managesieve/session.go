package managesieve

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	msieve "github.com/migadu/go-managesieve/managesieve"
	"github.com/migadu/go-managesieve/managesieveserver"
	"github.com/migadu/go-sieve"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
)

const ManageSieveMaxLineLength = 8192 // ManageSieve commands can be longer than POP3

// ManageSieveSession implements the go-managesieve Session interfaces: the
// library owns the RFC 5804 wire protocol (parsing, literals, SASL framing,
// STARTTLS, state machine), while this adapter supplies sora's business
// logic — authentication (incl. master credentials), script storage in
// PostgreSQL, go-sieve validation, quotas, rate limiting, and metrics.
type ManageSieveSession struct {
	server.Session
	mutex         sync.RWMutex
	mutexHelper   *server.MutexTimeoutHelper
	server        *ManageSieveServer
	conn          net.Conn // Connection to the client (pre-STARTTLS conn; used for peer identity and teardown)
	authenticated bool     // Flag to indicate if the user has been authenticated
	ctx           context.Context
	cancel        context.CancelFunc

	useMasterDB bool   // Pin session to master DB after a write to ensure consistency
	releaseConn func() // Function to release connection from limiter
	startTime   time.Time
}

var (
	_ managesieveserver.Session      = (*ManageSieveSession)(nil)
	_ managesieveserver.SessionLogin = (*ManageSieveSession)(nil)
)

// Shared wire responses. Uncoded *Error messages are emitted verbatim after
// "NO ", so these preserve sora's historical response bytes exactly.
var (
	errAuthFailed    = &managesieveserver.Error{Message: "Authentication failed"}
	errTryLater      = &managesieveserver.Error{Code: "TRYLATER", Message: "Service temporarily unavailable"}
	errNonExistent   = &managesieveserver.Error{Code: "NONEXISTENT", Message: "Script does not exist"}
	errServerBusy    = &managesieveserver.Error{Message: "Server busy, try again later"}
	errSessionClosed = &managesieveserver.Error{Message: "Session closed", Close: true}
	errDelayQueueFul = &managesieveserver.Error{Message: "Too many concurrent authentication attempts. Please try again later."}
)

// --- Authentication ---

// AuthenticatePlain implements the SASL PLAIN authentication business logic.
// The library has already handled the wire exchange (literal/continuation
// framing, base64, NUL splitting, empty-password cheap reject) and the
// transport-security and re-authentication gates. ctx is the library's
// per-command context: it aborts delay waits and DB calls promptly when the
// connection or server goes away mid-command.
func (s *ManageSieveSession) AuthenticatePlain(ctx context.Context, authzID, authnID, password string) error {
	start := time.Now()
	success := false
	defer func() {
		if !success {
			// Track failed authentication if not already successful
			metrics.AuthenticationAttempts.WithLabelValues("managesieve", s.server.name, s.server.hostname, "failure").Inc()
			metrics.CriticalOperationDuration.WithLabelValues("managesieve_authentication").Observe(time.Since(start).Seconds())
		}
	}()

	s.DebugLog("sasl plain authentication", "authz_id", authzID, "authn_id", authnID)

	// Parse authentication-identity to check for suffix (master username)
	authnParsed, parseErr := server.NewAddress(authnID)

	var accountID int64
	var impersonating bool
	var targetAddress *server.Address

	// 1. Check for Master Username Authentication (user@domain.com@MASTER_USERNAME)
	if parseErr == nil && len(s.server.masterUsername) > 0 && authnParsed.HasSuffix() && checkMasterCredential(authnParsed.Suffix(), s.server.masterUsername) {
		// Rate-limit the master-password check. The master password is a
		// tenant-wide credential, so it must not be brute-forceable
		// unthrottled.
		netConn := s.conn
		proxyInfo := s.proxyInfo()
		remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
		if err := server.ApplyAuthenticationDelay(ctx, s.server.authLimiter, remoteAddr, "MANAGESIEVE-MASTER"); err != nil {
			if errors.Is(err, server.ErrDelayQueueFull) {
				return errDelayQueueFul
			}
			// Context cancelled or other error - close connection
			return &managesieveserver.Error{Message: "Authentication failed", Close: true}
		}
		if s.server.authLimiter != nil {
			if err := s.server.authLimiter.CanAttemptAuthWithProxy(ctx, netConn, proxyInfo, authnParsed.BaseAddress()); err != nil {
				s.DebugLog("rate limited", "error", err)
				// Same response as bad credentials so rate-limit state isn't an oracle.
				return errAuthFailed
			}
		}

		// Suffix matches MasterUsername, authenticate with MasterPassword
		if len(s.server.masterPassword) > 0 && checkMasterCredential(password, s.server.masterPassword) {
			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, authnParsed.BaseAddress(), true)
			}
			// Determine target user to impersonate
			targetUserToImpersonate := authzID
			if targetUserToImpersonate == "" {
				// No authorization identity provided, use base address from authnID
				targetUserToImpersonate = authnParsed.BaseAddress()
			}

			s.DebugLog("master username authenticated, attempting impersonation", "master_username", authnParsed.Suffix(), "target_user", targetUserToImpersonate)

			address, err := server.NewAddress(targetUserToImpersonate)
			if err != nil {
				s.WarnLog("failed to parse impersonation target", "target_user", targetUserToImpersonate, "error", err)
				return &managesieveserver.Error{Message: "Invalid impersonation target user format"}
			}

			accountID, err = s.server.rdb.GetActiveAccountIDByAddressWithRetry(ctx, address.BaseAddress())
			if err != nil {
				s.WarnLog("failed to get account id for impersonation target", "target_user", targetUserToImpersonate, "error", err)
				return &managesieveserver.Error{Message: "Impersonation target user not found"}
			}

			targetAddress = &address
			impersonating = true
		} else {
			// Record failed master password authentication (feeds progressive
			// delay / blocking so the tenant-wide master password can't be
			// brute-forced).
			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, authnParsed.BaseAddress(), false)
			}
			// Master username suffix was provided but master password was wrong - fail immediately
			return &managesieveserver.Error{Message: "Invalid master credentials"}
		}
	}

	// 2. Check for Master SASL Authentication (traditional)
	if !impersonating && len(s.server.masterSASLUsername) > 0 && len(s.server.masterSASLPassword) > 0 {
		// Constant-time comparison to avoid a timing side-channel on the
		// tenant-wide master credentials.
		if checkMasterCredential(authnID, s.server.masterSASLUsername) && checkMasterCredential(password, s.server.masterSASLPassword) {
			// Network gate: master SASL is a tenant-wide impersonation
			// capability. Anchored to the real socket peer (cannot be forged
			// via PROXY/XCLIENT forwarding).
			if !s.server.masterSASLGate.Allowed(s.conn.RemoteAddr()) {
				s.WarnLog("master SASL credentials valid but source not in master_sasl_allowed_networks; rejecting", "peer", server.GetAddrString(s.conn.RemoteAddr()))
				return errAuthFailed
			}
			if authzID == "" {
				s.DebugLog("master sasl authentication successful but no authorization identity", "authn_id", authnID)
				return &managesieveserver.Error{Message: "Master SASL login requires an authorization identity."}
			}

			s.DebugLog("master sasl user authenticated, attempting impersonation", "authn_id", authnID, "authz_id", authzID)

			// Log in as the authzID without a password check
			address, err := server.NewAddress(authzID)
			if err != nil {
				s.WarnLog("failed to parse impersonation target", "target_user", authzID, "error", err)
				return &managesieveserver.Error{Message: "Invalid impersonation target user format"}
			}

			// Resolve the account by the base address (stripping any +detail
			// or @suffix), consistent with the master-username path above and
			// the IMAP/POP3 backends.
			accountID, err = s.server.rdb.GetActiveAccountIDByAddressWithRetry(ctx, address.BaseAddress())
			if err != nil {
				s.WarnLog("failed to get account id for impersonation target", "target_user", authzID, "error", err)
				return &managesieveserver.Error{Message: "Impersonation target user not found"}
			}

			targetAddress = &address
			impersonating = true
		}
	}

	// If not using master SASL, perform regular authentication
	if !impersonating {
		// For regular ManageSieve, we don't support proxy authentication
		if authzID != "" && authzID != authnID {
			s.DebugLog("proxy authentication requires master credentials", "authz_id", authzID, "authn_id", authnID)
			return &managesieveserver.Error{Message: "Proxy authentication requires master_sasl_username and master_sasl_password to be configured"}
		}

		address, err := server.NewAddress(authnID)
		if err != nil {
			s.WarnLog("invalid address format", "error", err)
			return &managesieveserver.Error{Message: "Invalid username format"}
		}

		s.DebugLog("authentication attempt", "address", address.FullAddress())

		netConn := s.conn
		proxyInfo := s.proxyInfo()

		// Apply progressive authentication delay BEFORE any other checks
		remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
		if err := server.ApplyAuthenticationDelay(ctx, s.server.authLimiter, remoteAddr, "MANAGESIEVE-SASL"); err != nil {
			if errors.Is(err, server.ErrDelayQueueFull) {
				// Delay queue full - reject immediately to prevent goroutine exhaustion
				s.InfoLog("delay queue full, rejecting connection", "address", address.FullAddress())
				return errDelayQueueFul
			}
			// Context cancelled or other error - close connection
			return &managesieveserver.Error{Message: "Authentication failed", Close: true}
		}

		// Check authentication rate limiting after delay
		if s.server.authLimiter != nil {
			if err := s.server.authLimiter.CanAttemptAuthWithProxy(ctx, netConn, proxyInfo, address.FullAddress()); err != nil {
				s.DebugLog("rate limited", "error", err)
				// Same response as a bad-credential failure so the rate-limit
				// state isn't an observable oracle. (security-audit M14)
				return errAuthFailed
			}
		}

		accountID, err = s.server.Authenticate(ctx, address.BaseAddress(), password)
		if err != nil {
			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, address.FullAddress(), false)
			}
			s.DebugLog("authentication failed")
			return errAuthFailed
		}

		// Record successful attempt
		if s.server.authLimiter != nil {
			s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, address.FullAddress(), true)
		}

		targetAddress = &address
	}

	if err := s.completeAuthentication(ctx, *targetAddress, accountID, impersonating, start); err != nil {
		return err
	}
	success = true
	return nil
}

// Login implements the non-standard LOGIN verb the backend has historically
// accepted. The library has already handled unquoting and the TLS and
// re-authentication gates. ctx is the library's per-command context.
func (s *ManageSieveSession) Login(ctx context.Context, username, password string) error {
	start := time.Now()

	address, err := server.NewAddress(username)
	if err != nil {
		s.DebugLog("invalid address", "error", err)
		return &managesieveserver.Error{Message: "Invalid address"}
	}

	netConn := s.conn
	proxyInfo := s.proxyInfo()

	// Apply progressive authentication delay BEFORE any other checks
	remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
	if err := server.ApplyAuthenticationDelay(ctx, s.server.authLimiter, remoteAddr, "MANAGESIEVE-LOGIN"); err != nil {
		if errors.Is(err, server.ErrDelayQueueFull) {
			// Delay queue full - reject immediately to prevent goroutine exhaustion
			s.InfoLog("delay queue full, rejecting connection", "username", username)
			return errDelayQueueFul
		}
		// Context cancelled or other error - close connection
		return &managesieveserver.Error{Message: "Authentication failed", Close: true}
	}

	// Check authentication rate limiting after delay
	if s.server.authLimiter != nil {
		if err := s.server.authLimiter.CanAttemptAuthWithProxy(ctx, netConn, proxyInfo, address.FullAddress()); err != nil {
			var rateLimitErr *server.RateLimitError
			if errors.As(err, &rateLimitErr) {
				s.InfoLog("rate limit exceeded",
					"address", address.FullAddress(),
					"reason", rateLimitErr.Reason,
					"failure_count", rateLimitErr.FailureCount,
					"blocked_until", rateLimitErr.BlockedUntil.Format(time.RFC3339))
			} else {
				s.DebugLog("rate limited", "error", err)
			}
			// Same response as a bad-credential failure so the rate-limit
			// state isn't an observable oracle. (security-audit M14)
			return errAuthFailed
		}
	}

	// Master username authentication: user@domain.com@MASTER_USERNAME
	authSuccess := false
	masterAuthUsed := false
	var accountID int64
	if len(s.server.masterUsername) > 0 && address.HasSuffix() && checkMasterCredential(address.Suffix(), s.server.masterUsername) {
		// Suffix matches MasterUsername, authenticate with MasterPassword
		if len(s.server.masterPassword) > 0 && checkMasterCredential(password, s.server.masterPassword) {
			s.DebugLog("master username authentication successful", "address", address.BaseAddress(), "master_username", address.Suffix())
			authSuccess = true
			masterAuthUsed = true
			// Use base address (without suffix) to get account
			accountID, err = s.server.rdb.GetActiveAccountIDByAddressWithRetry(ctx, address.BaseAddress())
			if err != nil {
				s.WarnLog("failed to get account id", "address", address.BaseAddress(), "error", err)
				if s.server.authLimiter != nil {
					s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, address.BaseAddress(), false)
				}
				metrics.AuthenticationAttempts.WithLabelValues("managesieve", s.server.name, s.server.hostname, "failure").Inc()
				return errAuthFailed
			}
		} else {
			// Record failed master password authentication
			metrics.AuthenticationAttempts.WithLabelValues("managesieve", s.server.name, s.server.hostname, "failure").Inc()
			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, address.BaseAddress(), false)
			}
			// Master username suffix was provided but master password was wrong - fail immediately
			return &managesieveserver.Error{Message: "Invalid master credentials"}
		}
	}

	// Try master SASL password authentication (traditional)
	if !authSuccess && len(s.server.masterSASLUsername) > 0 && len(s.server.masterSASLPassword) > 0 {
		if checkMasterCredential(address.BaseAddress(), s.server.masterSASLUsername) && checkMasterCredential(password, s.server.masterSASLPassword) {
			// Network gate: anchored to the real socket peer (cannot be
			// forged via PROXY/XCLIENT forwarding).
			if !s.server.masterSASLGate.Allowed(s.conn.RemoteAddr()) {
				s.WarnLog("master SASL credentials valid but source not in master_sasl_allowed_networks; rejecting", "peer", server.GetAddrString(s.conn.RemoteAddr()))
				metrics.AuthenticationAttempts.WithLabelValues("managesieve", s.server.name, s.server.hostname, "failure").Inc()
				return errAuthFailed
			}
			s.DebugLog("master sasl password authentication successful", "address", address.BaseAddress())
			authSuccess = true
			masterAuthUsed = true
			accountID, err = s.server.rdb.GetActiveAccountIDByAddressWithRetry(ctx, address.BaseAddress())
			if err != nil {
				s.WarnLog("failed to get account id for master user", "address", address.BaseAddress(), "error", err)
				if s.server.authLimiter != nil {
					s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, address.BaseAddress(), false)
				}
				metrics.AuthenticationAttempts.WithLabelValues("managesieve", s.server.name, s.server.hostname, "failure").Inc()
				return errAuthFailed
			}
		}
	}

	// If master password didn't work, try regular authentication
	if !authSuccess {
		accountID, err = s.server.Authenticate(ctx, address.BaseAddress(), password)
		if err != nil {
			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, address.FullAddress(), false)
			}
			metrics.AuthenticationAttempts.WithLabelValues("managesieve", s.server.name, s.server.hostname, "failure").Inc()
			return errAuthFailed
		}
	}

	// Record successful attempt
	if s.server.authLimiter != nil {
		s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, address.FullAddress(), true)
	}

	return s.completeAuthentication(ctx, address, accountID, masterAuthUsed, start)
}

// completeAuthentication updates session state, counters, metrics, and
// connection tracking after a successful credential check. Shared by
// AuthenticatePlain and Login. ctx is the per-command context; state that
// outlives the command (the termination poller) stays on the session context.
func (s *ManageSieveSession) completeAuthentication(ctx context.Context, address server.Address, accountID int64, masterAuthUsed bool, start time.Time) error {
	// Check if the command or session was cancelled during authentication logic
	if ctx.Err() != nil || s.ctx.Err() != nil {
		s.DebugLog("request aborted, aborting session update")
		return errSessionClosed
	}

	// Acquire write lock for updating session authentication state
	acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout(ctx)
	if !acquired {
		s.WarnLog("failed to acquire write lock", "operation", "authenticate")
		return errServerBusy
	}
	defer release()

	s.User = server.NewUser(address, accountID)

	// Increment authenticated connections counter
	s.server.authenticatedConnections.Add(1)

	// Log authentication success. Regular auth via Authenticate() already
	// logs in server.go with cached/method; master auth is logged here.
	if masterAuthUsed {
		duration := time.Since(start)
		s.InfoLog("authentication successful", "address", address.BaseAddress(), "account_id", accountID, "cached", false, "method", "master", "duration", fmt.Sprintf("%.3fs", duration.Seconds()))
	}

	// Track successful authentication
	metrics.AuthenticationAttempts.WithLabelValues("managesieve", s.server.name, s.server.hostname, "success").Inc()
	metrics.AuthenticatedConnectionsCurrent.WithLabelValues("managesieve", s.server.name, s.server.hostname).Inc()
	metrics.CriticalOperationDuration.WithLabelValues("managesieve_authentication").Observe(time.Since(start).Seconds())

	// IMPORTANT: Set authenticated flag AFTER incrementing both counters to
	// prevent a race: if the session closes between counter increments and
	// flag setting, cleanup won't decrement.
	s.authenticated = true

	// Register connection for tracking
	s.registerConnection(ctx, address.FullAddress())

	// Start termination poller to check for kick commands
	s.startTerminationPoller()

	// Track domain and user connection activity
	if s.User != nil {
		metrics.TrackDomainConnection("managesieve", s.Domain())
		metrics.TrackUserActivity("managesieve", s.FullAddress(), "connection", 1)
	}

	return nil
}

// proxyInfo returns the PROXY-protocol peer info for rate limiting, when the
// connection arrived through a PROXY header.
func (s *ManageSieveSession) proxyInfo() *server.ProxyProtocolInfo {
	if s.ProxyIP != "" {
		return &server.ProxyProtocolInfo{SrcIP: s.RemoteIP}
	}
	return nil
}

// --- Script operations ---

// sessionState snapshots the account and master-DB pin under the read lock,
// deriving from the library's per-command ctx a context that respects the
// session's master-DB pinning. Basing everything on the command context means
// blocked lock waits and DB calls abort promptly when the connection or
// server goes away mid-command (the mutex helper additionally merges in the
// session context).
func (s *ManageSieveSession) sessionState(ctx context.Context, command string) (accountID int64, readCtx context.Context, err error) {
	if ctx.Err() != nil || s.ctx.Err() != nil {
		s.DebugLog("request aborted", "command", command)
		return 0, nil, errSessionClosed
	}
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		s.WarnLog("failed to acquire read lock", "command", command)
		return 0, nil, errServerBusy
	}
	accountID = s.AccountID()
	useMaster := s.useMasterDB
	release()

	readCtx = ctx
	if useMaster {
		readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	}
	return accountID, readCtx, nil
}

// pinToMasterDB pins the session to the master DB after a write so subsequent
// reads in this session observe it (read replicas may lag). It deliberately
// uses the session context, NOT the per-command context: a write that commits
// just under the command deadline must still pin, or the command replies OK
// while the next read silently hits a lagging replica (read-your-writes lost).
// The flag set is a microsecond operation; the lock helper merges the session
// context so teardown still aborts the wait.
func (s *ManageSieveSession) pinToMasterDB(command string) {
	acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout(s.ctx)
	if !acquired {
		s.WarnLog("failed to acquire write lock", "command", command, "purpose", "pin_session")
		return
	}
	s.useMasterDB = true
	release()
}

// validateSieveScript validates content with go-sieve against the server's
// enabled extensions, rendering failures as a quoted error string (safe
// against response splitting even though the error echoes script tokens).
func (s *ManageSieveSession) validateSieveScript(content string) error {
	options := sieve.DefaultOptions()
	// Configure extensions based on server configuration.
	// If no extensions are configured, none are supported.
	options.EnabledExtensions = s.server.supportedExtensions
	if _, err := sieve.Load(strings.NewReader(content), options); err != nil {
		return &managesieveserver.Error{Message: msieve.Quote("Script validation failed: " + msieve.SanitizeText(err.Error()))}
	}
	return nil
}

// ListScripts implements managesieveserver.Session.
func (s *ManageSieveSession) ListScripts(ctx context.Context) ([]msieve.ScriptInfo, error) {
	ctx, cancel := applyCommandTimeout(ctx, "LISTSCRIPTS", s.server.commandTimeouts)
	defer cancel()
	accountID, readCtx, err := s.sessionState(ctx, "LISTSCRIPTS")
	if err != nil {
		return nil, err
	}

	scripts, dbErr := s.server.rdb.GetUserScriptsWithRetry(readCtx, accountID)
	if dbErr != nil {
		return nil, errTryLater
	}

	infos := make([]msieve.ScriptInfo, 0, len(scripts))
	for _, script := range scripts {
		infos = append(infos, msieve.ScriptInfo{Name: script.Name, Active: script.Active})
	}
	return infos, nil
}

// GetScript implements managesieveserver.Session.
func (s *ManageSieveSession) GetScript(ctx context.Context, name string) (string, error) {
	ctx, cancel := applyCommandTimeout(ctx, "GETSCRIPT", s.server.commandTimeouts)
	defer cancel()
	accountID, readCtx, err := s.sessionState(ctx, "GETSCRIPT")
	if err != nil {
		return "", err
	}

	script, dbErr := s.server.rdb.GetScriptByNameWithRetry(readCtx, name, accountID)
	if dbErr != nil {
		if dbErr == consts.ErrDBNotFound {
			return "", errNonExistent
		}
		return "", errTryLater
	}
	return script.Script, nil
}

// PutScript implements managesieveserver.Session. The library has validated
// the name and enforced the size bound; this validates the Sieve content and
// stores it.
func (s *ManageSieveSession) PutScript(ctx context.Context, name, content string) (bool, error) {
	start := time.Now()
	ctx, cancel := applyCommandTimeout(ctx, "PUTSCRIPT", s.server.commandTimeouts)
	defer cancel()
	accountID, readCtx, err := s.sessionState(ctx, "PUTSCRIPT")
	if err != nil {
		return false, err
	}

	if err := s.validateSieveScript(content); err != nil {
		return false, err
	}

	script, dbErr := s.server.rdb.GetScriptByNameWithRetry(readCtx, name, accountID)
	if dbErr != nil && dbErr != consts.ErrDBNotFound {
		return false, errTryLater
	}

	updated := false
	if script != nil {
		if _, err := s.server.rdb.UpdateScriptWithRetry(ctx, script.ID, accountID, name, content); err != nil {
			return false, errTryLater
		}
		updated = true
	} else {
		if _, err := s.server.rdb.CreateScriptWithRetry(ctx, accountID, name, content); err != nil {
			if errors.Is(err, db.ErrSieveScriptLimitReached) {
				return false, &managesieveserver.Error{Code: "QUOTA/MAXSCRIPTS", Message: "Too many scripts for this account"}
			}
			return false, errTryLater
		}
	}

	s.pinToMasterDB("PUTSCRIPT")

	// Track script upload
	metrics.ManageSieveScriptsUploaded.Inc()
	metrics.CriticalOperationDuration.WithLabelValues("managesieve_putscript").Observe(time.Since(start).Seconds())

	// Track domain and user activity - PUTSCRIPT is script processing intensive!
	if s.User != nil {
		metrics.TrackDomainCommand("managesieve", s.Domain(), "PUTSCRIPT")
		metrics.TrackUserActivity("managesieve", s.FullAddress(), "command", 1)
	}
	return updated, nil
}

// CheckScript implements managesieveserver.Session. Validation only; sora
// emits no warnings.
func (s *ManageSieveSession) CheckScript(ctx context.Context, content string) (string, error) {
	ctx, cancel := applyCommandTimeout(ctx, "CHECKSCRIPT", s.server.commandTimeouts)
	defer cancel()
	if ctx.Err() != nil || s.ctx.Err() != nil {
		s.DebugLog("request aborted", "command", "CHECKSCRIPT")
		return "", errSessionClosed
	}
	if err := s.validateSieveScript(content); err != nil {
		return "", err
	}
	return "", nil
}

// SetActive implements managesieveserver.Session. An empty name deactivates
// all scripts (RFC 5804 §2.8); activation re-validates the stored script.
func (s *ManageSieveSession) SetActive(ctx context.Context, name string) error {
	start := time.Now()
	ctx, cancel := applyCommandTimeout(ctx, "SETACTIVE", s.server.commandTimeouts)
	defer cancel()
	accountID, readCtx, err := s.sessionState(ctx, "SETACTIVE")
	if err != nil {
		return err
	}

	if name == "" {
		if err := s.server.rdb.DeactivateAllScriptsWithRetry(ctx, accountID); err != nil {
			return errTryLater
		}
		s.pinToMasterDB("SETACTIVE")
		metrics.CriticalOperationDuration.WithLabelValues("managesieve_setactive").Observe(time.Since(start).Seconds())
		return nil
	}

	script, dbErr := s.server.rdb.GetScriptByNameWithRetry(readCtx, name, accountID)
	if dbErr != nil {
		if dbErr == consts.ErrDBNotFound {
			return errNonExistent
		}
		return errTryLater
	}

	// Validate the script before activating it
	if err := s.validateSieveScript(script.Script); err != nil {
		return err
	}

	if err := s.server.rdb.SetScriptActiveWithRetry(ctx, script.ID, accountID, true); err != nil {
		return errTryLater
	}

	s.pinToMasterDB("SETACTIVE")

	// Track script activation
	metrics.ManageSieveScriptsActivated.Inc()
	metrics.CriticalOperationDuration.WithLabelValues("managesieve_setactive").Observe(time.Since(start).Seconds())
	return nil
}

// DeleteScript implements managesieveserver.Session. The active script is
// protected (RFC 5804 §2.10).
func (s *ManageSieveSession) DeleteScript(ctx context.Context, name string) error {
	ctx, cancel := applyCommandTimeout(ctx, "DELETESCRIPT", s.server.commandTimeouts)
	defer cancel()
	accountID, readCtx, err := s.sessionState(ctx, "DELETESCRIPT")
	if err != nil {
		return err
	}

	script, dbErr := s.server.rdb.GetScriptByNameWithRetry(readCtx, name, accountID)
	if dbErr != nil {
		if dbErr == consts.ErrDBNotFound {
			return errNonExistent
		}
		return errTryLater
	}

	// RFC 5804 §2.10: the active script MUST NOT be deleted; the client must
	// first deactivate it via SETACTIVE "".
	if script.Active {
		return &managesieveserver.Error{Code: "ACTIVE", Message: "Cannot delete the active script; deactivate it first"}
	}

	if err := s.server.rdb.DeleteScriptByIDWithRetry(ctx, script.ID, accountID); err != nil {
		return errTryLater
	}

	s.pinToMasterDB("DELETESCRIPT")
	return nil
}

// RenameScript implements managesieveserver.Session. The rename is a single
// atomic UPDATE: the UNIQUE (account_id, name) constraint resolves new-name
// collisions, so there is no read-then-write (TOCTOU) window and no exposure
// to read-replica lag. The script's active state is preserved.
func (s *ManageSieveSession) RenameScript(ctx context.Context, oldName, newName string) error {
	ctx, cancel := applyCommandTimeout(ctx, "RENAMESCRIPT", s.server.commandTimeouts)
	defer cancel()
	accountID, _, err := s.sessionState(ctx, "RENAMESCRIPT")
	if err != nil {
		return err
	}

	renameErr := s.server.rdb.RenameScriptWithRetry(ctx, accountID, oldName, newName)
	switch {
	case renameErr == nil:
		s.pinToMasterDB("RENAMESCRIPT")
		return nil
	case errors.Is(renameErr, consts.ErrDBNotFound):
		return errNonExistent
	case errors.Is(renameErr, consts.ErrDBUniqueViolation):
		return &managesieveserver.Error{Code: "ALREADYEXISTS", Message: "A script with the new name already exists"}
	default:
		return errTryLater
	}
}

// HaveSpace implements managesieveserver.Session (RFC 5804 §2.5). The library
// has already rejected sizes above max_script_size; this enforces the
// per-account script-count quota. The name is significant: a HAVESPACE for an
// existing script is a replacement, which does not increase the script count.
func (s *ManageSieveSession) HaveSpace(ctx context.Context, name string, _ int64) error {
	// HAVESPACE is advisory; if the DB layer is unavailable we optimistically
	// report space (only the size bound applies). In production rdb is always
	// set; this guard also keeps the handler usable from unit tests that
	// construct a minimal session.
	if s.server.rdb == nil {
		return nil
	}

	ctx, cancel := applyCommandTimeout(ctx, "HAVESPACE", s.server.commandTimeouts)
	defer cancel()
	accountID, readCtx, err := s.sessionState(ctx, "HAVESPACE")
	if err != nil {
		return err
	}

	scripts, dbErr := s.server.rdb.GetUserScriptsWithRetry(readCtx, accountID)
	if dbErr != nil {
		return errTryLater
	}
	exists := false
	for _, sc := range scripts {
		if sc.Name == name {
			exists = true
			break
		}
	}
	if !exists && len(scripts) >= db.MaxScriptsPerAccount() {
		return &managesieveserver.Error{Code: "QUOTA/MAXSCRIPTS", Message: "Maximum number of scripts reached"}
	}
	return nil
}

// --- Teardown ---

func (s *ManageSieveSession) closeWithoutLock() error {
	// Observe connection duration
	metrics.ConnectionDuration.WithLabelValues("managesieve", s.server.name, s.server.hostname).Observe(time.Since(s.startTime).Seconds())

	// Decrement connection counters
	totalCount := s.server.totalConnections.Add(-1)
	var authCount int64 = 0

	s.conn.Close()

	// Remove session from active tracking
	s.server.removeSession(s)

	// Release connection from limiter
	if s.releaseConn != nil {
		s.releaseConn()
		s.releaseConn = nil // Prevent double release
	}

	// Prometheus metrics - connection closed
	metrics.ConnectionsCurrent.WithLabelValues("managesieve", s.server.name, s.server.hostname).Dec()

	if s.User != nil {
		// If authenticated, decrement the authenticated connections counter
		if s.authenticated {
			metrics.AuthenticatedConnectionsCurrent.WithLabelValues("managesieve", s.server.name, s.server.hostname).Dec()
			authCount = s.server.authenticatedConnections.Add(-1)

			// Unregister connection from tracker
			s.unregisterConnection()
		} else {
			authCount = s.server.authenticatedConnections.Load()
		}
		s.InfoLog("session closed", "total_connections", totalCount, "authenticated_connections", authCount)
		s.User = nil
		s.Id = ""
		s.authenticated = false
		if s.cancel != nil {
			s.cancel()
		}
	} else {
		authCount = s.server.authenticatedConnections.Load()
		s.InfoLog("session closed unauthenticated", "total_connections", totalCount, "authenticated_connections", authCount)
		if s.cancel != nil {
			s.cancel()
		}
	}

	return nil
}

func (s *ManageSieveSession) Close() error {
	// Check if context is already canceled (during shutdown)
	select {
	case <-s.ctx.Done():
		// Context is canceled, skip lock acquisition during shutdown
		return s.closeWithoutLock()
	default:
		// Acquire write lock for cleanup
		acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout(s.ctx)
		if !acquired {
			s.InfoLog("failed to acquire write lock within timeout", "operation", "close")
			// Continue with close even if we can't get the lock
			return s.closeWithoutLock()
		}
		defer release()
		return s.closeWithoutLock()
	}
}

// registerConnection registers the connection in the connection tracker.
// It runs synchronously within the authenticating command, so it is bounded
// by the per-command context (plus the query timeout).
func (s *ManageSieveSession) registerConnection(ctx context.Context, email string) {
	if s.server.connTracker != nil && s.User != nil {
		// Use configured database query timeout for connection tracking (database INSERT)
		queryTimeout := s.server.rdb.GetQueryTimeout()
		ctx, cancel := context.WithTimeout(ctx, queryTimeout)
		defer cancel()

		clientAddr := server.GetAddrString(s.conn.RemoteAddr())

		if err := s.server.connTracker.RegisterConnection(ctx, s.AccountID(), email, "ManageSieve", clientAddr); err != nil {
			s.InfoLog("rejected connection registration", "error", err)
		}
	}
}

// unregisterConnection removes the connection from the connection tracker
func (s *ManageSieveSession) unregisterConnection() {
	if s.server.connTracker != nil && s.User != nil {
		// Use configured database query timeout for connection tracking (database DELETE)
		queryTimeout := s.server.rdb.GetQueryTimeout()
		ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
		defer cancel()

		clientAddr := server.GetAddrString(s.conn.RemoteAddr())

		if err := s.server.connTracker.UnregisterConnection(ctx, s.AccountID(), "ManageSieve", clientAddr); err != nil {
			s.WarnLog("failed to unregister connection", "error", err)
		}
	}
}

// startTerminationPoller starts a goroutine that waits for kick notifications
func (s *ManageSieveSession) startTerminationPoller() {
	if s.server.connTracker == nil || s.User == nil {
		return
	}

	// Capture everything the poller goroutine needs up front: the session
	// teardown nils s.User (which AccountID/InfoLog read) unsynchronized
	// with this goroutine. s.conn is set once at construction, so the
	// captured conn is safe to close from here.
	accountID := s.AccountID()
	user := s.FullAddress()
	sessionID := s.Id
	conn := s.conn

	// Register session for kick notifications and get a channel that closes on kick
	kickChan := s.server.connTracker.RegisterSession(accountID)

	go func() {
		// Unregister when done
		defer s.server.connTracker.UnregisterSession(accountID, kickChan)

		select {
		case <-kickChan:
			// Kick notification received - close connection. Log with the
			// captured identity; s.InfoLog would re-read session fields that
			// a concurrent teardown may be nilling.
			logger.Info("connection kicked, disconnecting",
				"protocol", s.Protocol, "user", user, "account_id", accountID, "session", sessionID)
			conn.Close()
		case <-s.ctx.Done():
			// Session ended normally
		}
	}()
}

func checkMasterCredential(provided string, actual []byte) bool {
	return subtle.ConstantTimeCompare([]byte(provided), actual) == 1
}
