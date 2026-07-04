package managesieve

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/migadu/go-sieve"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
)

const ManageSieveMaxLineLength = 8192 // ManageSieve commands can be longer than POP3

type ManageSieveSession struct {
	server.Session
	mutex         sync.RWMutex
	mutexHelper   *server.MutexTimeoutHelper
	server        *ManageSieveServer
	conn          *net.Conn          // Connection to the client
	authenticated bool               // Flag to indicate if the user has been authenticated
	ctx           context.Context    // Context for this session
	cancel        context.CancelFunc // Function to cancel the session's context

	reader      *bufio.Reader
	writer      *bufio.Writer
	isTLS       bool
	useMasterDB bool   // Pin session to master DB after a write to ensure consistency
	releaseConn func() // Function to release connection from limiter
	startTime   time.Time
}

func (s *ManageSieveSession) sendRawLine(line string) {
	s.writer.WriteString(line + "\r\n")
}

// quoteSieveString renders s as a ManageSieve quoted string (RFC 5804 §1.2),
// escaping backslash and double-quote so an embedded quote in a script name or
// client tag cannot break response framing.
func quoteSieveString(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}

// sanitizeResponseText neutralizes control characters (CR, LF, NUL and other C0/DEL
// bytes) in server-supplied human-readable text — e.g. SIEVE validation errors that
// echo attacker-controlled script tokens — so it cannot inject a forged response line
// when embedded in a NO/OK response. Pair with quoteSieveString for RFC 5804 framing.
func sanitizeResponseText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// validateScriptName enforces basic ManageSieve script-name hygiene (RFC 5804 §1.6:
// names are UTF-8 strings). Rejects empty names, invalid UTF-8, and control characters
// (C0/DEL), which have no legitimate use and could corrupt logs or LIST/GETSCRIPT output.
func validateScriptName(name string) error {
	if name == "" {
		return fmt.Errorf("script name cannot be empty")
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("script name must be valid UTF-8")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("script name must not contain control characters")
		}
	}
	return nil
}

func (s *ManageSieveSession) sendCapabilities() {
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(s.ctx)
	if !acquired {
		s.WarnLog("failed to acquire read lock", "operation", "sendCapabilities")
		// Send minimal capabilities if lock fails
		s.sendRawLine(fmt.Sprintf("\"IMPLEMENTATION\" \"%s\"", "ManageSieve"))
		s.sendRawLine("\"VERSION\" \"1.0\"")
		s.sendRawLine("\"SIEVE\" \"fileinto vacation\"")
		return
	}
	defer release()

	s.sendRawLine(fmt.Sprintf("\"IMPLEMENTATION\" \"%s\"", "ManageSieve"))
	s.sendRawLine("\"VERSION\" \"1.0\"")

	// Build capabilities: builtin + configured extensions
	capabilities := GetSieveCapabilities(s.server.supportedExtensions)
	extensionsStr := strings.Join(capabilities, " ")
	s.sendRawLine(fmt.Sprintf("\"SIEVE\" \"%s\"", extensionsStr))

	if s.server.tlsConfig != nil && s.server.useStartTLS && !s.isTLS {
		s.sendRawLine("\"STARTTLS\"")
		// Before STARTTLS: Don't advertise SASL mechanisms (RFC 5804 security requirement)
		s.sendRawLine("\"SASL\" \"\"")
	} else if s.isTLS || s.server.insecureAuth {
		// After STARTTLS or on implicit TLS: Advertise available SASL mechanisms
		s.sendRawLine("\"SASL\" \"PLAIN\"")
	}
	if s.server.maxScriptSize > 0 {
		s.sendRawLine(fmt.Sprintf("\"MAXSCRIPTSIZE\" \"%d\"", s.server.maxScriptSize))
	}
}

func (s *ManageSieveSession) handleConnection() {
	defer s.Close()

	// Complete the deferred TLS handshake (implicit-TLS listeners). The helper
	// walks the Unwrap() chain, so the handshake runs through the PROXY conn
	// and consumes any ClientHello bytes buffered alongside the PROXY header.
	// Failure is a silent close: no plaintext banner onto a broken TLS stream.
	if _, err := server.PerformDeferredTLSHandshake(*s.conn); err != nil {
		s.WarnLog("tls handshake failed", "error", err)
		return
	}

	s.sendCapabilitiesGreeting()

	for {
		// Set timeout for reading command
		// During pre-auth phase: use auth_idle_timeout (if configured), otherwise use commandTimeout
		// After authentication: use commandTimeout
		if !s.authenticated && s.server.authIdleTimeout > 0 {
			(*s.conn).SetReadDeadline(time.Now().Add(s.server.authIdleTimeout))
		} else if s.server.commandTimeout > 0 {
			(*s.conn).SetReadDeadline(time.Now().Add(s.server.commandTimeout))
		} else {
			(*s.conn).SetReadDeadline(time.Time{}) // No timeout
		}

		line, err := server.ReadBoundedLine(s.reader, ManageSieveMaxLineLength)
		if err != nil {
			if err == server.ErrLineTooLong {
				s.sendResponse(`NO "Command line too long"`)
				s.writer.Flush()
				s.WarnLog("line too long, closing connection")
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.sendRawLine("BYE (TRYLATER) \"Connection timed out due to inactivity, please reconnect\"")
				s.writer.Flush()
				s.WarnLog("connection timed out")
				return
			} else if err == io.EOF {
				s.DebugLog("client dropped connection")
			} else {
				s.WarnLog("read error", "error", err)
			}
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Use proper command parser that handles quoted strings with spaces
		// ManageSieve doesn't use tags, so hasTag=false
		_, command, args, parseErr := server.ParseLine(line, false)
		if parseErr != nil {
			s.sendResponse(fmt.Sprintf("NO Invalid command syntax: %v\r\n", parseErr))
			continue
		}

		// For backward compatibility, create parts array (command + args)
		parts := make([]string, 0, len(args)+1)
		parts = append(parts, command)
		parts = append(parts, args...)

		// If debug logging is active, it might log the raw command.
		// This ensures that if any such logging exists, it will be of a masked line.
		// This is a defensive change as the direct logging is not visible in this file.
		s.DebugLog("client command", "line", helpers.MaskSensitive(line, command, "AUTHENTICATE", "LOGIN"))

		// Set command execution deadline (for processing the command, not reading it)
		commandDeadline := time.Time{} // Zero time means no deadline
		if s.server.commandTimeout > 0 {
			commandDeadline = time.Now().Add(s.server.commandTimeout)
		}
		(*s.conn).SetDeadline(commandDeadline)

		switch command {
		case "CAPABILITY":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("managesieve", "CAPABILITY", status).Inc()
				metrics.CommandDuration.WithLabelValues("managesieve", "CAPABILITY").Observe(time.Since(start).Seconds())
			}
			if s.handleCapability() {
				recordMetrics("success")
			} else {
				recordMetrics("failure")
			}

		case "LOGIN":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("managesieve", "LOGIN", status).Inc()
				metrics.CommandDuration.WithLabelValues("managesieve", "LOGIN").Observe(time.Since(start).Seconds())
			}

			// RFC 5804 state machine: reject re-authentication on an already
			// authenticated connection (prevents authenticated-connection counter and
			// termination-poller goroutine leaks; close cleans up only once).
			if s.authenticated {
				s.sendResponse("NO Already authenticated\r\n")
				recordMetrics("failure")
				continue
			}

			// Cleartext-auth gate: LOGIN carries the password as a plaintext command
			// argument, so it MUST honor the same transport-security policy as
			// AUTHENTICATE (handleAuthenticate). Without this, the non-standard LOGIN
			// command would bypass the STARTTLS requirement AUTHENTICATE enforces.
			if !s.isTLS && !s.server.insecureAuth {
				s.sendResponse("NO Authentication not permitted on insecure connection. Use STARTTLS first.\r\n")
				recordMetrics("failure")
				continue
			}

			if len(parts) < 3 {
				s.sendResponse("NO Syntax: LOGIN address password\r\n")
				recordMetrics("failure")
				continue
			}
			// Remove quotes if present
			userAddress := server.UnquoteString(parts[1])
			password := server.UnquoteString(parts[2])

			address, err := server.NewAddress(userAddress)
			if err != nil {
				s.DebugLog("invalid address", "error", err)
				s.sendResponse("NO Invalid address\r\n")
				recordMetrics("failure")
				continue
			}

			// Get connection and proxy info for rate limiting
			netConn := *s.conn
			var proxyInfo *server.ProxyProtocolInfo
			if s.ProxyIP != "" {
				proxyInfo = &server.ProxyProtocolInfo{
					SrcIP: s.RemoteIP,
				}
			}

			// Apply progressive authentication delay BEFORE any other checks
			remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
			if err := server.ApplyAuthenticationDelay(s.ctx, s.server.authLimiter, remoteAddr, "MANAGESIEVE-LOGIN"); err != nil {
				if errors.Is(err, server.ErrDelayQueueFull) {
					// Delay queue full - reject immediately to prevent goroutine exhaustion
					s.InfoLog("delay queue full, rejecting connection", "username", parts[0])
					s.sendResponse("NO Too many concurrent authentication attempts. Please try again later.\r\n")
					recordMetrics("failure")
					continue
				}
				// Context cancelled or other error - close connection
				return
			}

			// Check authentication rate limiting after delay
			if s.server.authLimiter != nil {
				if err := s.server.authLimiter.CanAttemptAuthWithProxy(s.ctx, netConn, proxyInfo, address.FullAddress()); err != nil {
					// Check if this is a rate limit error
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

					// Same response as a bad-credential failure (the "NO Authentication failed"
					// line below) so the rate-limit state isn't an observable oracle. (security-audit M14)
					s.sendResponse("NO Authentication failed\r\n")
					recordMetrics("failure")
					continue
				}
			}

			// Master username authentication: user@domain.com@MASTER_USERNAME
			// Check if suffix matches configured MasterUsername
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
					accountID, err = s.server.rdb.GetActiveAccountIDByAddressWithRetry(s.ctx, address.BaseAddress())
					if err != nil {
						s.WarnLog("failed to get account id", "address", address.BaseAddress(), "error", err)
						// Record failed attempt
						if s.server.authLimiter != nil {
							s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, address.BaseAddress(), false)
						}
						metrics.AuthenticationAttempts.WithLabelValues("managesieve", s.server.name, s.server.hostname, "failure").Inc()
						s.sendResponse("NO Authentication failed\r\n")
						recordMetrics("failure")
						continue
					}
				} else {
					// Record failed master password authentication
					metrics.AuthenticationAttempts.WithLabelValues("managesieve", s.server.name, s.server.hostname, "failure").Inc()
					if s.server.authLimiter != nil {
						s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, address.BaseAddress(), false)
					}

					// Master username suffix was provided but master password was wrong - fail immediately
					s.sendResponse("NO Invalid master credentials\r\n")
					recordMetrics("failure")
					continue
				}
			}

			// Try master SASL password authentication (traditional)
			if !authSuccess && len(s.server.masterSASLUsername) > 0 && len(s.server.masterSASLPassword) > 0 {
				if checkMasterCredential(address.BaseAddress(), s.server.masterSASLUsername) && checkMasterCredential(password, s.server.masterSASLPassword) {
					// Network gate: master SASL is a tenant-wide impersonation capability.
					// Anchored to the real socket peer (cannot be forged via PROXY/XCLIENT forwarding).
					if !s.server.masterSASLGate.Allowed((*s.conn).RemoteAddr()) {
						s.WarnLog("master SASL credentials valid but source not in master_sasl_allowed_networks; rejecting", "peer", server.GetAddrString((*s.conn).RemoteAddr()))
						metrics.AuthenticationAttempts.WithLabelValues("managesieve", s.server.name, s.server.hostname, "failure").Inc()
						s.sendResponse("NO Authentication failed\r\n")
						recordMetrics("failure")
						continue
					}
					s.DebugLog("master sasl password authentication successful", "address", address.BaseAddress())
					authSuccess = true
					masterAuthUsed = true
					// For master password, we need to get the user ID
					accountID, err = s.server.rdb.GetActiveAccountIDByAddressWithRetry(s.ctx, address.BaseAddress())
					if err != nil {
						s.WarnLog("failed to get account id for master user", "address", address.BaseAddress(), "error", err)
						// Record failed attempt
						if s.server.authLimiter != nil {
							s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, address.BaseAddress(), false)
						}
						metrics.AuthenticationAttempts.WithLabelValues("managesieve", s.server.name, s.server.hostname, "failure").Inc()
						s.sendResponse("NO Authentication failed\r\n")
						recordMetrics("failure")
						continue
					}
				}
			}

			// If master password didn't work, try regular authentication
			if !authSuccess {
				accountID, err = s.server.Authenticate(s.ctx, address.BaseAddress(), password)
				if err != nil {
					// Record failed attempt
					if s.server.authLimiter != nil {
						s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, address.FullAddress(), false)
					}
					metrics.AuthenticationAttempts.WithLabelValues("managesieve", s.server.name, s.server.hostname, "failure").Inc()
					s.sendResponse("NO Authentication failed\r\n")
					recordMetrics("failure")
					continue
				}
				authSuccess = true
			}

			// Record successful attempt
			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, address.FullAddress(), true)
			}

			// Check if the context was cancelled during authentication logic
			if s.ctx.Err() != nil {
				s.DebugLog("request aborted, aborting session update")
				recordMetrics("failure")
				continue
			}

			// Acquire write lock for updating session authentication state
			acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout(s.ctx)
			if !acquired {
				s.WarnLog("failed to acquire write lock", "command", "LOGIN")
				s.sendResponse("NO Server busy, try again later\r\n")
				recordMetrics("failure")
				continue
			}
			defer release()

			s.User = server.NewUser(address, accountID)

			// Increment authenticated connections counter
			s.server.authenticatedConnections.Add(1)

			// Log authentication success
			// Note: Regular auth via Authenticate() already logs in server.go with cached/method
			// For master password auth, we log here with method=master
			if masterAuthUsed {
				duration := time.Since(start)
				s.InfoLog("authentication successful", "address", address.BaseAddress(), "account_id", accountID, "cached", false, "method", "master", "duration", fmt.Sprintf("%.3fs", duration.Seconds()))
			}

			// Track successful authentication
			metrics.AuthenticationAttempts.WithLabelValues("managesieve", s.server.name, s.server.hostname, "success").Inc()
			metrics.AuthenticatedConnectionsCurrent.WithLabelValues("managesieve", s.server.name, s.server.hostname).Inc()

			// IMPORTANT: Set authenticated flag AFTER incrementing both counters to prevent race condition
			// If session closes between counter increments and flag setting, cleanup won't decrement
			s.authenticated = true

			// Track domain and user connection activity
			if s.User != nil {
				metrics.TrackDomainConnection("managesieve", s.Domain())
				metrics.TrackUserActivity("managesieve", s.FullAddress(), "connection", 1)
			}

			// Register connection for tracking
			s.registerConnection(address.FullAddress())

			// Start termination poller to check for kick commands
			s.startTerminationPoller()

			s.sendResponse("OK Authenticated\r\n")
			recordMetrics("success")

		case "AUTHENTICATE":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("managesieve", "AUTHENTICATE", status).Inc()
				metrics.CommandDuration.WithLabelValues("managesieve", "AUTHENTICATE").Observe(time.Since(start).Seconds())
			}
			if s.handleAuthenticate(parts) {
				recordMetrics("success")
			} else {
				recordMetrics("failure")
			}

		case "LISTSCRIPTS":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("managesieve", "LISTSCRIPTS", status).Inc()
				metrics.CommandDuration.WithLabelValues("managesieve", "LISTSCRIPTS").Observe(time.Since(start).Seconds())
			}

			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				recordMetrics("failure")
				continue
			}
			if s.handleListScripts() {
				recordMetrics("success")
			} else {
				recordMetrics("failure")
			}

		case "GETSCRIPT":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("managesieve", "GETSCRIPT", status).Inc()
				metrics.CommandDuration.WithLabelValues("managesieve", "GETSCRIPT").Observe(time.Since(start).Seconds())
			}

			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				recordMetrics("failure")
				continue
			}
			if len(parts) < 2 {
				s.sendResponse("NO Syntax: GETSCRIPT scriptName\r\n")
				recordMetrics("failure")
				continue
			}
			scriptName := parts[1]
			if s.handleGetScript(scriptName) {
				recordMetrics("success")
			} else {
				recordMetrics("failure")
			}

		case "PUTSCRIPT":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("managesieve", "PUTSCRIPT", status).Inc()
				metrics.CommandDuration.WithLabelValues("managesieve", "PUTSCRIPT").Observe(time.Since(start).Seconds())
			}

			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				recordMetrics("failure")
				continue
			}
			if len(parts) < 3 {
				s.sendResponse("NO Syntax: PUTSCRIPT scriptName scriptContent\r\n")
				recordMetrics("failure")
				continue
			}
			scriptName := parts[1]
			scriptContent := parts[2]

			// Check if script content is a literal string {length+} or {length}
			if strings.HasPrefix(scriptContent, "{") && (strings.HasSuffix(scriptContent, "}") || strings.HasSuffix(scriptContent, "+}")) {
				hasPlus := strings.HasSuffix(scriptContent, "+}")

				// Extract length from {length} or {length+}
				lengthStr := strings.TrimPrefix(scriptContent, "{")
				lengthStr = strings.TrimSuffix(lengthStr, "}")
				lengthStr = strings.TrimSuffix(lengthStr, "+")

				length64, parseErr := strconv.ParseInt(lengthStr, 10, 64)
				if parseErr != nil || length64 < 0 {
					s.sendResponse("NO Invalid literal string length\r\n")
					recordMetrics("failure")
					continue
				}
				if length64 > s.server.maxScriptSize {
					s.sendResponse(fmt.Sprintf("NO (QUOTA/MAXSIZE) \"Script size %d exceeds maximum allowed size %d\"\r\n", length64, s.server.maxScriptSize))
					recordMetrics("failure")
					continue
				}
				length := int(length64)

				if !hasPlus {
					// Send continuation response (+ ready for literal data) only for synchronizing literals
					s.sendResponse("+\r\n")
				}

				// Read the literal content (length bytes)
				var buf bytes.Buffer
				if _, err := io.CopyN(&buf, s.reader, int64(length)); err != nil {
					s.sendResponse("NO Failed to read literal string content\r\n")
					// Bypass metrics for client socket timeouts (network transmission errors)
					continue
				}
				literalContent := buf.Bytes()

				// Read the trailing CRLF after literal (RFC 5804 compliance)
				server.ReadBoundedLine(s.reader, ManageSieveMaxLineLength)

				// Reset the metric timer NOW to exclude the time the client took to upload the script
				start = time.Now()

				scriptContent = string(literalContent)
			}

			if s.handlePutScript(scriptName, scriptContent) {
				recordMetrics("success")
			} else {
				recordMetrics("failure")
			}

		case "CHECKSCRIPT":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("managesieve", "CHECKSCRIPT", status).Inc()
				metrics.CommandDuration.WithLabelValues("managesieve", "CHECKSCRIPT").Observe(time.Since(start).Seconds())
			}

			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				recordMetrics("failure")
				continue
			}
			if len(parts) < 2 {
				s.sendResponse("NO Syntax: CHECKSCRIPT scriptContent\r\n")
				recordMetrics("failure")
				continue
			}
			scriptContent := parts[1]

			// Check if script content is a literal string {length+} or {length}
			if strings.HasPrefix(scriptContent, "{") && (strings.HasSuffix(scriptContent, "}") || strings.HasSuffix(scriptContent, "+}")) {
				hasPlus := strings.HasSuffix(scriptContent, "+}")

				// Extract length from {length} or {length+}
				lengthStr := strings.TrimPrefix(scriptContent, "{")
				lengthStr = strings.TrimSuffix(lengthStr, "}")
				lengthStr = strings.TrimSuffix(lengthStr, "+")

				length64, parseErr := strconv.ParseInt(lengthStr, 10, 64)
				if parseErr != nil || length64 < 0 {
					s.sendResponse("NO Invalid literal string length\r\n")
					recordMetrics("failure")
					continue
				}
				if length64 > s.server.maxScriptSize {
					s.sendResponse(fmt.Sprintf("NO (QUOTA/MAXSIZE) \"Script size %d exceeds maximum allowed size %d\"\r\n", length64, s.server.maxScriptSize))
					recordMetrics("failure")
					continue
				}
				length := int(length64)

				if !hasPlus {
					// Send continuation response (+ ready for literal data) only for synchronizing literals
					s.sendResponse("+\r\n")
				}

				// Read the literal content (length bytes)
				var buf bytes.Buffer
				if _, err := io.CopyN(&buf, s.reader, int64(length)); err != nil {
					s.sendResponse("NO Failed to read literal string content\r\n")
					// Bypass metrics for client socket timeouts (network transmission errors)
					continue
				}
				literalContent := buf.Bytes()

				// Read the trailing CRLF after literal (RFC 5804 compliance)
				server.ReadBoundedLine(s.reader, ManageSieveMaxLineLength)

				// Reset the metric timer NOW to exclude the time the client took to upload the script
				start = time.Now()

				scriptContent = string(literalContent)
			} else {
				scriptContent = server.UnquoteString(scriptContent)
			}

			if s.handleCheckScript(scriptContent) {
				recordMetrics("success")
			} else {
				recordMetrics("failure")
			}

		case "HAVESPACE":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("managesieve", "HAVESPACE", status).Inc()
				metrics.CommandDuration.WithLabelValues("managesieve", "HAVESPACE").Observe(time.Since(start).Seconds())
			}

			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				recordMetrics("failure")
				continue
			}
			if len(parts) < 3 {
				s.sendResponse("NO Syntax: HAVESPACE scriptName scriptSize\r\n")
				recordMetrics("failure")
				continue
			}
			scriptName := strings.TrimSpace(server.UnquoteString(parts[1]))
			sizeStr := parts[2]
			size64, parseErr := strconv.ParseInt(sizeStr, 10, 64)
			if parseErr != nil || size64 < 0 {
				s.sendResponse("NO Invalid script size\r\n")
				recordMetrics("failure")
				continue
			}

			if s.handleHaveSpace(scriptName, size64) {
				recordMetrics("success")
			} else {
				recordMetrics("failure")
			}

		case "RENAMESCRIPT":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("managesieve", "RENAMESCRIPT", status).Inc()
				metrics.CommandDuration.WithLabelValues("managesieve", "RENAMESCRIPT").Observe(time.Since(start).Seconds())
			}

			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				recordMetrics("failure")
				continue
			}
			if len(parts) < 3 {
				s.sendResponse("NO Syntax: RENAMESCRIPT oldName newName\r\n")
				recordMetrics("failure")
				continue
			}
			oldName := strings.TrimSpace(server.UnquoteString(parts[1]))
			newName := strings.TrimSpace(server.UnquoteString(parts[2]))

			if s.handleRenameScript(oldName, newName) {
				recordMetrics("success")
			} else {
				recordMetrics("failure")
			}

		case "SETACTIVE":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("managesieve", "SETACTIVE", status).Inc()
				metrics.CommandDuration.WithLabelValues("managesieve", "SETACTIVE").Observe(time.Since(start).Seconds())
			}

			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				recordMetrics("failure")
				continue
			}
			if len(parts) < 2 {
				s.sendResponse("NO Syntax: SETACTIVE scriptName\r\n")
				recordMetrics("failure")
				continue
			}
			scriptName := parts[1]
			if s.handleSetActive(scriptName) {
				recordMetrics("success")
			} else {
				recordMetrics("failure")
			}

		case "DELETESCRIPT":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("managesieve", "DELETESCRIPT", status).Inc()
				metrics.CommandDuration.WithLabelValues("managesieve", "DELETESCRIPT").Observe(time.Since(start).Seconds())
			}

			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				recordMetrics("failure")
				continue
			}
			if len(parts) < 2 {
				s.sendResponse("NO Syntax: DELETESCRIPT scriptName\r\n")
				recordMetrics("failure")
				continue
			}
			scriptName := parts[1]
			if s.handleDeleteScript(scriptName) {
				recordMetrics("success")
			} else {
				recordMetrics("failure")
			}

		case "STARTTLS":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("managesieve", "STARTTLS", status).Inc()
				metrics.CommandDuration.WithLabelValues("managesieve", "STARTTLS").Observe(time.Since(start).Seconds())
			}

			if !s.server.useStartTLS || s.server.tlsConfig == nil {
				s.sendResponse("NO STARTTLS not supported\r\n")
				recordMetrics("failure")
				continue
			}
			if s.isTLS {
				s.sendResponse("NO TLS already active\r\n")
				recordMetrics("failure")
				continue
			}
			// RFC 5804 §2.2: STARTTLS resets to the non-authenticated state and prior
			// knowledge MUST be discarded. Rather than silently re-authenticate, reject
			// STARTTLS once authenticated (real clients always negotiate TLS before auth).
			if s.authenticated {
				s.sendResponse("NO STARTTLS not permitted after authentication\r\n")
				recordMetrics("failure")
				continue
			}
			// RFC 5804 §2.2 / RFC 3207: reject (and close) if the client pipelined any
			// data after STARTTLS before the TLS handshake. Such buffered plaintext may
			// be a MITM command-injection attempt; we must not process it post-TLS.
			if s.reader.Buffered() > 0 {
				s.WarnLog("STARTTLS rejected: client sent data before TLS handshake")
				s.sendResponse("NO Pipelined data after STARTTLS is not allowed\r\n")
				recordMetrics("failure")
				return
			}
			s.sendResponse("OK Begin TLS negotiation\r\n")

			// Upgrade the connection to TLS
			tlsConn := tls.Server(*s.conn, s.server.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				s.WarnLog("tls handshake failed", "error", err)
				s.sendResponse("NO TLS handshake failed\r\n")
				recordMetrics("failure")
				continue
			}

			// Check if context was cancelled during handshake
			if s.ctx.Err() != nil {
				s.DebugLog("request aborted after handshake")
				recordMetrics("failure")
				return
			}

			// Acquire write lock for updating connection state
			acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout(s.ctx)
			if !acquired {
				s.WarnLog("failed to acquire write lock", "command", "STARTTLS")
				s.sendResponse("NO Server busy, try again later\r\n")
				recordMetrics("failure")
				continue
			}

			// Replace the connection and readers/writers
			*s.conn = tlsConn
			s.reader = bufio.NewReader(tlsConn)
			s.writer = bufio.NewWriter(tlsConn)
			s.isTLS = true

			// RFC 5804 requires sending capabilities immediately after STARTTLS
			s.sendCapabilitiesGreeting()

			// Release lock immediately after updating connection state
			release()

			s.DebugLog("tls negotiation successful")
			recordMetrics("success")

		case "NOOP":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("managesieve", "NOOP", status).Inc()
				metrics.CommandDuration.WithLabelValues("managesieve", "NOOP").Observe(time.Since(start).Seconds())
			}

			// Handle NOOP with optional tag argument (e.g., NOOP "STARTTLS-RESYNC-CAPA")
			// sieve-connect uses this to verify capabilities were received
			if len(parts) > 1 {
				tag := server.UnquoteString(parts[1])
				s.sendResponse(fmt.Sprintf("OK (TAG %s) \"Done\"\r\n", quoteSieveString(tag)))
			} else {
				s.sendResponse("OK\r\n")
			}
			recordMetrics("success")

		case "LOGOUT":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("managesieve", "LOGOUT", status).Inc()
				metrics.CommandDuration.WithLabelValues("managesieve", "LOGOUT").Observe(time.Since(start).Seconds())
			}

			s.sendResponse("OK Goodbye\r\n")
			s.writer.Flush()

			recordMetrics("success")
			// Return and let defer s.Close() handle cleanup
			return

		default:
			s.sendResponse("NO Unknown command\r\n")
		}

		// Flush response and check for timeout
		if err := s.writer.Flush(); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.WarnLog("command exceeded timeout", "command", command, "timeout", s.server.commandTimeout)

				// Track timeout event in metrics
				metrics.CommandTimeoutsTotal.WithLabelValues("managesieve", command).Inc()

				// Try to send error message if possible
				(*s.conn).SetDeadline(time.Now().Add(5 * time.Second)) // Brief window to send error
				s.sendResponse("NO Command exceeded timeout\r\n")
				s.writer.Flush()
				return
			}
			s.WarnLog("error flushing response", "command", command, "error", err)
			return
		}

		// Clear deadline after successful command completion
		(*s.conn).SetDeadline(time.Time{})
	}
}

func (s *ManageSieveSession) sendCapabilitiesGreeting() {
	s.sendCapabilities()

	implementationName := "Sora"
	var okMessage string
	// Check if STARTTLS is supported and not yet active for the (STARTTLS) hint in OK response
	if s.server.tlsConfig != nil && s.server.useStartTLS && !s.isTLS {
		okMessage = fmt.Sprintf("OK (STARTTLS) \"%s\" ManageSieve server ready.", implementationName)
	} else {
		okMessage = fmt.Sprintf("OK \"%s\" ManageSieve server ready.", implementationName)
	}
	s.sendRawLine(okMessage)
	s.writer.Flush() // Flush all greeting lines
}

func (s *ManageSieveSession) sendResponse(response string) {
	s.writer.WriteString(response)
	s.writer.Flush()
}

func (s *ManageSieveSession) handleCapability() bool {
	s.sendCapabilities()
	s.sendRawLine("OK")
	s.writer.Flush()
	return true
}

func (s *ManageSieveSession) handleListScripts() bool {
	// Check if the context is closing before proceeding.
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted", "command", "LISTSCRIPTS")
		s.sendResponse("NO Session closed\r\n")
		return false
	}

	// Acquire a read lock only to get the necessary session state.
	// A write lock is not needed for a read-only command.
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(s.ctx)
	if !acquired {
		s.WarnLog("failed to acquire read lock", "command", "LISTSCRIPTS")
		s.sendResponse("NO Server busy, try again later\r\n")
		return false
	}
	// Copy the necessary state under lock.
	accountID := s.AccountID()
	useMaster := s.useMasterDB
	release() // Release lock before DB call

	// Create a context for read operations that respects session pinning
	readCtx := s.ctx
	if useMaster {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	scripts, err := s.server.rdb.GetUserScriptsWithRetry(readCtx, accountID)
	if err != nil {
		s.sendResponse("NO (TRYLATER) \"Service temporarily unavailable\"\r\n")
		return false
	}

	if len(scripts) == 0 {
		s.sendResponse("OK\r\n")
		return true
	}

	for _, script := range scripts {
		line := quoteSieveString(script.Name)
		if script.Active {
			line += " ACTIVE"
		}
		s.sendRawLine(line)
	}
	s.sendRawLine("OK")
	s.writer.Flush()
	return true
}

func (s *ManageSieveSession) handleGetScript(name string) bool {
	// Check if the context is closing before proceeding.
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted", "command", "GETSCRIPT")
		s.sendResponse("NO Session closed\r\n")
		return false
	}

	// Remove surrounding quotes if present (same as PUTSCRIPT)
	name = strings.TrimSpace(server.UnquoteString(name))

	// Acquire a read lock only to get the necessary session state.
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(s.ctx)
	if !acquired {
		s.WarnLog("failed to acquire read lock", "command", "GETSCRIPT")
		s.sendResponse("NO Server busy, try again later\r\n")
		return false
	}
	// Copy the necessary state under lock.
	accountID := s.AccountID()
	useMaster := s.useMasterDB
	release() // Release lock before DB call

	// Create a context for read operations that respects session pinning
	readCtx := s.ctx
	if useMaster {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	script, err := s.server.rdb.GetScriptByNameWithRetry(readCtx, name, accountID)
	if err != nil {
		if err == consts.ErrDBNotFound {
			s.sendResponse("NO (NONEXISTENT) \"Script does not exist\"\r\n")
			return false
		}
		s.sendResponse("NO (TRYLATER) \"Service temporarily unavailable\"\r\n")
		return false
	}
	s.writer.WriteString(fmt.Sprintf("{%d}\r\n", len(script.Script)))
	s.writer.WriteString(script.Script)
	// RFC 5804 §2.9 / §4: the string literal is terminated by CRLF before the OK
	// response line. Without this, the OK is glued to the last script octet and
	// clients that re-sync on the literal's trailing CRLF desync.
	s.writer.WriteString("\r\n")
	s.writer.Flush()
	s.sendResponse("OK\r\n")
	return true
}

func (s *ManageSieveSession) handlePutScript(name, content string) bool {
	start := time.Now()
	// Check if the context is closing before proceeding.
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted", "command", "PUTSCRIPT")
		s.sendResponse("NO Session closed\r\n")
		return false
	}

	// Validate script name - non-empty, valid UTF-8, no control characters.
	name = strings.TrimSpace(server.UnquoteString(name)) // Remove surrounding quotes and whitespace
	if err := validateScriptName(name); err != nil {
		s.sendResponse(fmt.Sprintf("NO %s\r\n", quoteSieveString(err.Error())))
		return false
	}

	// Phase 1: Read session state
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(s.ctx)
	if !acquired {
		s.WarnLog("failed to acquire read lock", "command", "PUTSCRIPT")
		s.sendResponse("NO Server busy, try again later\r\n")
		return false
	}
	accountID := s.AccountID()
	useMaster := s.useMasterDB
	release()

	// Phase 2: Validate and perform DB operations
	if int64(len(content)) > s.server.maxScriptSize {
		s.sendResponse(fmt.Sprintf("NO (QUOTA/MAXSIZE) \"Script size %d exceeds maximum allowed size %d\"\r\n", len(content), s.server.maxScriptSize))
		return false
	}

	scriptReader := strings.NewReader(content)
	options := sieve.DefaultOptions()
	// Configure extensions based on server configuration
	// If no extensions are configured, none are supported
	options.EnabledExtensions = s.server.supportedExtensions
	_, err := sieve.Load(scriptReader, options)
	if err != nil {
		s.sendResponse(fmt.Sprintf("NO %s\r\n", quoteSieveString("Script validation failed: "+sanitizeResponseText(err.Error()))))
		return false
	}

	// Create a context for read operations that respects session pinning
	readCtx := s.ctx
	if useMaster {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	script, err := s.server.rdb.GetScriptByNameWithRetry(readCtx, name, accountID)
	if err != nil {
		if err != consts.ErrDBNotFound {
			s.sendResponse("NO (TRYLATER) \"Service temporarily unavailable\"\r\n")
			return false
		}
	}

	var responseMsg string
	if script != nil {
		_, err := s.server.rdb.UpdateScriptWithRetry(s.ctx, script.ID, accountID, name, content)
		if err != nil {
			s.sendResponse("NO (TRYLATER) \"Service temporarily unavailable\"\r\n")
			return false
		}

		responseMsg = "OK Script updated\r\n"
	} else {
		_, err = s.server.rdb.CreateScriptWithRetry(s.ctx, accountID, name, content)
		if err != nil {
			if errors.Is(err, db.ErrSieveScriptLimitReached) {
				s.sendResponse("NO (QUOTA/MAXSCRIPTS) \"Too many scripts for this account\"\r\n")
				return false
			}
			s.sendResponse("NO (TRYLATER) \"Service temporarily unavailable\"\r\n")
			return false
		}
		responseMsg = "OK Script stored\r\n"
	}

	// Phase 3: Update session state
	acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout(s.ctx)
	if !acquired {
		s.WarnLog("failed to acquire write lock", "command", "PUTSCRIPT", "purpose", "pin_session")
	} else {
		s.useMasterDB = true
		release()
	}

	// Track script upload
	metrics.ManageSieveScriptsUploaded.Inc()
	metrics.CriticalOperationDuration.WithLabelValues("managesieve_putscript").Observe(time.Since(start).Seconds())

	// Track domain and user activity - PUTSCRIPT is script processing intensive!
	if s.User != nil {
		metrics.TrackDomainCommand("managesieve", s.Domain(), "PUTSCRIPT")
		metrics.TrackUserActivity("managesieve", s.FullAddress(), "command", 1)
	}
	s.sendResponse(responseMsg)
	return true
}

func (s *ManageSieveSession) handleCheckScript(content string) bool {
	// Check if the context is closing before proceeding.
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted", "command", "CHECKSCRIPT")
		s.sendResponse("NO Session closed\r\n")
		return false
	}

	if int64(len(content)) > s.server.maxScriptSize {
		s.sendResponse(fmt.Sprintf("NO (QUOTA/MAXSIZE) \"Script size %d exceeds maximum allowed size %d\"\r\n", len(content), s.server.maxScriptSize))
		return false
	}

	scriptReader := strings.NewReader(content)
	options := sieve.DefaultOptions()
	// Configure extensions based on server configuration
	// If no extensions are configured, none are supported
	options.EnabledExtensions = s.server.supportedExtensions
	_, err := sieve.Load(scriptReader, options)
	if err != nil {
		s.sendResponse(fmt.Sprintf("NO %s\r\n", quoteSieveString("Script validation failed: "+sanitizeResponseText(err.Error()))))
		return false
	}

	s.sendResponse("OK\r\n")
	return true
}

// handleHaveSpace implements RFC 5804 §2.5 HAVESPACE: it reports whether a script of the
// given name and size could be stored, without storing it. Capacity is bounded by the max
// script size and the per-account script-count quota. The name is significant: a HAVESPACE
// for an existing script is a replacement, which does not increase the script count.
func (s *ManageSieveSession) handleHaveSpace(name string, size int64) bool {
	// Check if the context is closing before proceeding.
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted", "command", "HAVESPACE")
		s.sendResponse("NO Session closed\r\n")
		return false
	}

	if size > s.server.maxScriptSize {
		s.sendResponse(fmt.Sprintf("NO (QUOTA/MAXSIZE) \"Script size %d exceeds maximum allowed size %d\"\r\n", size, s.server.maxScriptSize))
		return false
	}

	// Script-count quota (RFC 5804 §2.5) requires DB access. HAVESPACE is advisory, so if
	// the DB layer is unavailable we optimistically report space (only the size bound above
	// applies). In production rdb is always set; this guard also keeps the handler usable
	// from unit tests that construct a minimal session.
	if s.server.rdb != nil {
		// Read session state for the count-quota check (respecting session pinning).
		acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(s.ctx)
		if !acquired {
			s.WarnLog("failed to acquire read lock", "command", "HAVESPACE")
			s.sendResponse("NO Server busy, try again later\r\n")
			return false
		}
		accountID := s.AccountID()
		useMaster := s.useMasterDB
		release()

		readCtx := s.ctx
		if useMaster {
			readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
		}

		// A HAVESPACE for an existing script name is a replacement (count unchanged); a new
		// name would create a script and so must stay within the per-account script limit.
		scripts, err := s.server.rdb.GetUserScriptsWithRetry(readCtx, accountID)
		if err != nil {
			s.sendResponse("NO (TRYLATER) \"Service temporarily unavailable\"\r\n")
			return false
		}
		exists := false
		for _, sc := range scripts {
			if sc.Name == name {
				exists = true
				break
			}
		}
		if !exists && len(scripts) >= db.MaxScriptsPerAccount() {
			s.sendResponse("NO (QUOTA/MAXSCRIPTS) \"Maximum number of scripts reached\"\r\n")
			return false
		}
	}

	s.sendResponse("OK\r\n")
	return true
}

func (s *ManageSieveSession) handleRenameScript(oldName, newName string) bool {
	// Check if the context is closing before proceeding.
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted", "command", "RENAMESCRIPT")
		s.sendResponse("NO Session closed\r\n")
		return false
	}

	if oldName == "" {
		s.sendResponse("NO Script name cannot be empty\r\n")
		return false
	}
	// The new name is being created; hold it to the same hygiene as PUTSCRIPT.
	if err := validateScriptName(newName); err != nil {
		s.sendResponse(fmt.Sprintf("NO %s\r\n", quoteSieveString(err.Error())))
		return false
	}

	// Read session state
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(s.ctx)
	if !acquired {
		s.WarnLog("failed to acquire read lock", "command", "RENAMESCRIPT")
		s.sendResponse("NO Server busy, try again later\r\n")
		return false
	}
	accountID := s.AccountID()
	release()

	// Rename atomically in a single UPDATE. The UNIQUE (account_id, name) constraint
	// resolves new-name collisions, so there is no read-then-write (TOCTOU) window and
	// no exposure to read-replica lag. The script's active state is preserved.
	err := s.server.rdb.RenameScriptWithRetry(s.ctx, accountID, oldName, newName)
	switch {
	case err == nil:
		// Pin session to master so subsequent reads in this session see the rename.
		acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout(s.ctx)
		if !acquired {
			s.WarnLog("failed to acquire write lock", "command", "RENAMESCRIPT", "purpose", "pin_session")
		} else {
			s.useMasterDB = true
			release()
		}
		s.sendResponse("OK\r\n")
		return true
	case errors.Is(err, consts.ErrDBNotFound):
		s.sendResponse("NO (NONEXISTENT) \"Script does not exist\"\r\n")
		return false
	case errors.Is(err, consts.ErrDBUniqueViolation):
		s.sendResponse("NO (ALREADYEXISTS) \"A script with the new name already exists\"\r\n")
		return false
	default:
		s.sendResponse("NO (TRYLATER) \"Service temporarily unavailable\"\r\n")
		return false
	}
}

func (s *ManageSieveSession) handleSetActive(name string) bool {
	start := time.Now()
	// Check if the context is closing before proceeding.
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted", "command", "SETACTIVE")
		s.sendResponse("NO Session closed\r\n")
		return false
	}

	// Remove surrounding quotes if present (same as PUTSCRIPT)
	name = strings.TrimSpace(server.UnquoteString(name))

	// Phase 1: Read session state
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(s.ctx)
	if !acquired {
		s.WarnLog("failed to acquire read lock", "command", "SETACTIVE")
		s.sendResponse("NO Server busy, try again later\r\n")
		return false
	}
	accountID := s.AccountID()
	useMaster := s.useMasterDB
	release()

	// RFC 5804: SETACTIVE "" deactivates all scripts
	if name == "" {
		err := s.server.rdb.DeactivateAllScriptsWithRetry(s.ctx, accountID)
		if err != nil {
			s.sendResponse("NO (TRYLATER) \"Service temporarily unavailable\"\r\n")
			return false
		}

		// Phase 3: Update session state
		acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout(s.ctx)
		if !acquired {
			s.WarnLog("failed to acquire write lock", "command", "SETACTIVE", "purpose", "pin_session")
		} else {
			s.useMasterDB = true
			release()
		}

		metrics.CriticalOperationDuration.WithLabelValues("managesieve_setactive").Observe(time.Since(start).Seconds())
		s.sendResponse("OK\r\n")
		return true
	}

	// Phase 2: DB operations
	readCtx := s.ctx
	if useMaster {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	script, err := s.server.rdb.GetScriptByNameWithRetry(readCtx, name, accountID)
	if err != nil {
		if err == consts.ErrDBNotFound {
			s.sendResponse("NO (NONEXISTENT) \"Script does not exist\"\r\n")
			return false
		}
		s.sendResponse("NO (TRYLATER) \"Service temporarily unavailable\"\r\n")
		return false
	}

	// Validate the script before activating it
	scriptReader := strings.NewReader(script.Script)
	options := sieve.DefaultOptions()
	// Configure extensions based on server configuration
	// If no extensions are configured, none are supported
	options.EnabledExtensions = s.server.supportedExtensions
	_, err = sieve.Load(scriptReader, options)
	if err != nil {
		s.sendResponse(fmt.Sprintf("NO %s\r\n", quoteSieveString("Script validation failed: "+sanitizeResponseText(err.Error()))))
		return false
	}

	err = s.server.rdb.SetScriptActiveWithRetry(s.ctx, script.ID, accountID, true)
	if err != nil {
		s.sendResponse("NO (TRYLATER) \"Service temporarily unavailable\"\r\n")
		return false
	}

	// Phase 3: Update session state
	acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout(s.ctx)
	if !acquired {
		s.WarnLog("failed to acquire write lock", "command", "SETACTIVE", "purpose", "pin_session")
	} else {
		s.useMasterDB = true
		release()
	}

	// Track script activation
	metrics.ManageSieveScriptsActivated.Inc()
	metrics.CriticalOperationDuration.WithLabelValues("managesieve_setactive").Observe(time.Since(start).Seconds())

	s.sendResponse("OK\r\n")
	return true
}

func (s *ManageSieveSession) handleDeleteScript(name string) bool {
	// Check if the context is closing before proceeding.
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted", "command", "DELETESCRIPT")
		s.sendResponse("NO Session closed\r\n")
		return false
	}

	// Remove surrounding quotes if present (same as PUTSCRIPT)
	name = strings.TrimSpace(server.UnquoteString(name))

	// Phase 1: Read session state
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(s.ctx)
	if !acquired {
		s.WarnLog("failed to acquire read lock", "command", "DELETESCRIPT")
		s.sendResponse("NO Server busy, try again later\r\n")
		return false
	}
	accountID := s.AccountID()
	useMaster := s.useMasterDB
	release()

	// Phase 2: DB operations
	readCtx := s.ctx
	if useMaster {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	script, err := s.server.rdb.GetScriptByNameWithRetry(readCtx, name, accountID)
	if err != nil {
		if err == consts.ErrDBNotFound {
			s.sendResponse("NO (NONEXISTENT) \"Script does not exist\"\r\n")
			return false
		}
		s.sendResponse("NO (TRYLATER) \"Service temporarily unavailable\"\r\n") // RFC uses NO for server errors
		return false
	}

	// RFC 5804 §2.10: the active script MUST NOT be deleted; the client must first
	// deactivate it via SETACTIVE "". GetScriptByName populates script.Active.
	if script.Active {
		s.sendResponse("NO (ACTIVE) \"Cannot delete the active script; deactivate it first\"\r\n")
		return false
	}

	err = s.server.rdb.DeleteScriptByIDWithRetry(s.ctx, script.ID, accountID)
	if err != nil {
		s.sendResponse("NO (TRYLATER) \"Service temporarily unavailable\"\r\n")
		return false
	}

	// Phase 3: Update session state
	acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout(s.ctx)
	if !acquired {
		s.WarnLog("failed to acquire write lock", "command", "DELETESCRIPT", "purpose", "pin_session")
	} else {
		s.useMasterDB = true
		release()
	}
	s.sendResponse("OK Script deleted\r\n")
	return true
}

func (s *ManageSieveSession) closeWithoutLock() error {
	// Observe connection duration
	metrics.ConnectionDuration.WithLabelValues("managesieve", s.server.name, s.server.hostname).Observe(time.Since(s.startTime).Seconds())

	// Decrement connection counters
	totalCount := s.server.totalConnections.Add(-1)
	var authCount int64 = 0

	(*s.conn).Close()

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

func (s *ManageSieveSession) handleAuthenticate(parts []string) bool {
	// RFC 5804: AUTHENTICATE is only valid in the non-authenticated state. Rejecting
	// re-authentication also prevents leaking the authenticated-connection counter and
	// spawning a duplicate termination-poller goroutine (both would otherwise run again
	// on a second success while close cleans up only once). Checked before the failure
	// defer so a state-machine rejection isn't miscounted as an auth failure.
	if s.authenticated {
		s.sendResponse("NO Already authenticated\r\n")
		return false
	}

	start := time.Now()
	success := false
	defer func() {
		if !success {
			// Track failed authentication if not already successful
			metrics.AuthenticationAttempts.WithLabelValues("managesieve", s.server.name, s.server.hostname, "failure").Inc()
			metrics.CriticalOperationDuration.WithLabelValues("managesieve_authentication").Observe(time.Since(start).Seconds())
		}
	}()

	if len(parts) < 2 {
		s.sendResponse("NO Syntax: AUTHENTICATE mechanism\r\n")
		return false
	}

	// Check if authentication is allowed over non-TLS connection
	if !s.isTLS && !s.server.insecureAuth {
		s.sendResponse("NO Authentication not permitted on insecure connection. Use STARTTLS first.\r\n")
		return false
	}

	// Remove quotes from mechanism if present
	mechanism := server.UnquoteString(parts[1])
	mechanism = strings.ToUpper(mechanism)
	if mechanism != "PLAIN" {
		s.sendResponse("NO Unsupported authentication mechanism\r\n")
		return false
	}

	// Check if initial response is provided
	var authData string
	if len(parts) > 2 {
		// Initial response provided (either quoted string or literal)
		arg2 := parts[2]

		// Check if it's a literal string {number+} or {number}
		if strings.HasPrefix(arg2, "{") && (strings.HasSuffix(arg2, "}") || strings.HasSuffix(arg2, "+}")) {
			// Literal string - need to read the specified number of bytes
			literalStr := strings.TrimPrefix(arg2, "{")
			literalStr = strings.TrimSuffix(literalStr, "}")
			literalStr = strings.TrimSuffix(literalStr, "+")

			literalSize64, err := strconv.ParseInt(literalStr, 10, 64)
			if err != nil || literalSize64 < 0 || literalSize64 > 8192 {
				s.sendResponse("NO Invalid literal size\r\n")
				return false
			}
			literalSize := int(literalSize64)

			s.DebugLog("reading authenticate literal", "size_bytes", literalSize)

			// Read the literal data
			literalData := make([]byte, literalSize)
			_, err = io.ReadFull(s.reader, literalData)
			if err != nil {
				s.WarnLog("error reading literal data", "error", err)
				s.sendResponse("NO Authentication failed\r\n")
				return false
			}

			// Read the trailing CRLF after literal
			server.ReadBoundedLine(s.reader, ManageSieveMaxLineLength)

			authData = string(literalData)
		} else {
			// Quoted string - remove quotes and decode from base64
			authData = server.UnquoteString(arg2)
		}
	} else {
		// No initial response, send continuation
		s.sendResponse("\"\"\r\n")

		// Read the authentication data (bounded to avoid a pre-auth memory blow-up)
		authLine, err := server.ReadBoundedLine(s.reader, ManageSieveMaxLineLength)
		if err != nil {
			s.WarnLog("error reading auth data", "error", err)
			s.sendResponse("NO Authentication failed\r\n")
			return false
		}
		authData = strings.TrimSpace(authLine)

		// Check for cancellation
		if authData == "*" {
			s.sendResponse("NO Authentication cancelled\r\n")
			return false
		}

		// Remove quotes if present in continuation response
		authData = server.UnquoteString(authData)
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(authData)
	if err != nil {
		s.WarnLog("error decoding auth data", "error", err)
		s.sendResponse("NO Invalid authentication data\r\n")
		return false
	}

	// Parse SASL PLAIN format: [authz-id] \0 authn-id \0 password
	parts = strings.Split(string(decoded), "\x00")
	if len(parts) != 3 {
		s.WarnLog("invalid sasl plain format")
		s.sendResponse("NO Invalid authentication format\r\n")
		return false
	}

	authzID := parts[0]  // Authorization identity (who to act as)
	authnID := parts[1]  // Authentication identity (who is authenticating)
	password := parts[2] // Password

	// Reject empty passwords immediately - no rate limiting needed
	// Empty passwords are never valid under any condition
	if password == "" {
		s.sendResponse("NO Authentication failed\r\n")
		return false
	}

	s.DebugLog("sasl plain authentication", "authz_id", authzID, "authn_id", authnID)

	// Parse authentication-identity to check for suffix (master username or remotelookup token)
	authnParsed, parseErr := server.NewAddress(authnID)

	var accountID int64
	var impersonating bool
	var targetAddress *server.Address

	// 1. Check for Master Username Authentication (user@domain.com@MASTER_USERNAME)
	if parseErr == nil && len(s.server.masterUsername) > 0 && authnParsed.HasSuffix() && checkMasterCredential(authnParsed.Suffix(), s.server.masterUsername) {
		// Rate-limit the master-password check. The master password is a tenant-wide
		// credential; mirror LOGIN's master path (which throttles before its master
		// check) so it cannot be brute-forced unthrottled — the regular-auth block
		// below is already rate-limited, this branch previously was not.
		netConn := *s.conn
		var proxyInfo *server.ProxyProtocolInfo
		if s.ProxyIP != "" {
			proxyInfo = &server.ProxyProtocolInfo{SrcIP: s.RemoteIP}
		}
		remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
		if err := server.ApplyAuthenticationDelay(s.ctx, s.server.authLimiter, remoteAddr, "MANAGESIEVE-MASTER"); err != nil {
			if errors.Is(err, server.ErrDelayQueueFull) {
				s.sendResponse("NO Too many concurrent authentication attempts. Please try again later.\r\n")
				return false
			}
			return false
		}
		if s.server.authLimiter != nil {
			if err := s.server.authLimiter.CanAttemptAuthWithProxy(s.ctx, netConn, proxyInfo, authnParsed.BaseAddress()); err != nil {
				s.DebugLog("rate limited", "error", err)
				// Same response as bad credentials so rate-limit state isn't an oracle.
				s.sendResponse("NO Authentication failed\r\n")
				return false
			}
		}

		// Suffix matches MasterUsername, authenticate with MasterPassword
		if len(s.server.masterPassword) > 0 && checkMasterCredential(password, s.server.masterPassword) {
			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, authnParsed.BaseAddress(), true)
			}
			// Determine target user to impersonate
			targetUserToImpersonate := authzID
			if targetUserToImpersonate == "" {
				// No authorization identity provided, use base address from authnID
				targetUserToImpersonate = authnParsed.BaseAddress()
			}

			s.DebugLog("master username authenticated, attempting impersonation", "master_username", authnParsed.Suffix(), "target_user", targetUserToImpersonate)

			// Parse target user address
			address, err := server.NewAddress(targetUserToImpersonate)
			if err != nil {
				s.WarnLog("failed to parse impersonation target", "target_user", targetUserToImpersonate, "error", err)
				s.sendResponse("NO Invalid impersonation target user format\r\n")
				return false
			}

			accountID, err = s.server.rdb.GetActiveAccountIDByAddressWithRetry(s.ctx, address.BaseAddress())
			if err != nil {
				s.WarnLog("failed to get account id for impersonation target", "target_user", targetUserToImpersonate, "error", err)
				s.sendResponse("NO Impersonation target user not found\r\n")
				return false
			}

			targetAddress = &address
			impersonating = true
		} else {
			// Record failed master password authentication (feeds progressive delay /
			// blocking so the tenant-wide master password can't be brute-forced).
			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, authnParsed.BaseAddress(), false)
			}
			metrics.AuthenticationAttempts.WithLabelValues("managesieve", s.server.name, s.server.hostname, "failure").Inc()

			// Master username suffix was provided but master password was wrong - fail immediately
			s.sendResponse("NO Invalid master credentials\r\n")
			return false
		}
	}

	// 2. Check for Master SASL Authentication (traditional)
	if !impersonating && len(s.server.masterSASLUsername) > 0 && len(s.server.masterSASLPassword) > 0 {
		// Check if this is a master SASL login (constant-time comparison to avoid a
		// timing side-channel on the tenant-wide master credentials).
		if checkMasterCredential(authnID, s.server.masterSASLUsername) && checkMasterCredential(password, s.server.masterSASLPassword) {
			// Network gate: master SASL is a tenant-wide impersonation capability.
			// Anchored to the real socket peer (cannot be forged via PROXY/XCLIENT
			// forwarding). Mirrors the LOGIN master-SASL path so AUTHENTICATE cannot be
			// used to bypass master_sasl_allowed_networks.
			if !s.server.masterSASLGate.Allowed((*s.conn).RemoteAddr()) {
				s.WarnLog("master SASL credentials valid but source not in master_sasl_allowed_networks; rejecting", "peer", server.GetAddrString((*s.conn).RemoteAddr()))
				s.sendResponse("NO Authentication failed\r\n")
				return false
			}
			// Master SASL authentication successful
			if authzID == "" {
				s.DebugLog("master sasl authentication successful but no authorization identity", "authn_id", authnID)
				s.sendResponse("NO Master SASL login requires an authorization identity.\r\n")
				return false
			}

			s.DebugLog("master sasl user authenticated, attempting impersonation", "authn_id", authnID, "authz_id", authzID)

			// Log in as the authzID without a password check
			address, err := server.NewAddress(authzID)
			if err != nil {
				s.WarnLog("failed to parse impersonation target", "target_user", authzID, "error", err)
				s.sendResponse("NO Invalid impersonation target user format\r\n")
				return false
			}

			// Resolve the account by the base address (stripping any +detail or @suffix),
			// consistent with the master-username path above and the IMAP/POP3 backends.
			// Using FullAddress() here would fail to resolve impersonation targets that carry
			// a suffix/+detail (e.g. a master token forwarded by the proxy).
			accountID, err = s.server.rdb.GetActiveAccountIDByAddressWithRetry(s.ctx, address.BaseAddress())
			if err != nil {
				s.WarnLog("failed to get account id for impersonation target", "target_user", authzID, "error", err)
				s.sendResponse("NO Impersonation target user not found\r\n")
				return false
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
			s.sendResponse("NO Proxy authentication requires master_sasl_username and master_sasl_password to be configured\r\n")
			return false
		}

		// Authenticate the user
		address, err := server.NewAddress(authnID)
		if err != nil {
			s.WarnLog("invalid address format", "error", err)
			s.sendResponse("NO Invalid username format\r\n")
			return false
		}

		s.DebugLog("authentication attempt", "address", address.FullAddress())

		// Get connection and proxy info for rate limiting
		netConn := *s.conn
		var proxyInfo *server.ProxyProtocolInfo
		if s.ProxyIP != "" {
			proxyInfo = &server.ProxyProtocolInfo{
				SrcIP: s.RemoteIP,
			}
		}

		// Apply progressive authentication delay BEFORE any other checks
		remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
		if err := server.ApplyAuthenticationDelay(s.ctx, s.server.authLimiter, remoteAddr, "MANAGESIEVE-SASL"); err != nil {
			if errors.Is(err, server.ErrDelayQueueFull) {
				// Delay queue full - reject immediately to prevent goroutine exhaustion
				s.InfoLog("delay queue full, rejecting connection", "address", address.FullAddress())
				s.sendResponse("NO Too many concurrent authentication attempts. Please try again later.\r\n")
				return false
			}
			// Context cancelled or other error - close connection
			return false
		}

		// Check authentication rate limiting after delay
		if s.server.authLimiter != nil {
			if err := s.server.authLimiter.CanAttemptAuthWithProxy(s.ctx, netConn, proxyInfo, address.FullAddress()); err != nil {
				s.DebugLog("rate limited", "error", err)
				// Same response as a bad-credential failure (the "NO Authentication failed" line
				// below) so the rate-limit state isn't an observable oracle. (security-audit M14)
				s.sendResponse("NO Authentication failed\r\n")
				return false
			}
		}

		accountID, err = s.server.Authenticate(s.ctx, address.BaseAddress(), password)
		if err != nil {
			// Record failed attempt
			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, address.FullAddress(), false)
			}
			s.sendResponse("NO Authentication failed\r\n")
			s.DebugLog("authentication failed")
			return false
		}

		// Record successful attempt
		if s.server.authLimiter != nil {
			s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, address.FullAddress(), true)
		}

		targetAddress = &address
	}

	// Check if the context was cancelled during authentication logic
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted, aborting session update")
		return false
	}

	// Acquire write lock for updating session authentication state
	acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout(s.ctx)
	if !acquired {
		s.WarnLog("failed to acquire write lock", "command", "AUTHENTICATE")
		s.sendResponse("NO Server busy, try again later\r\n")
		return false
	}
	defer release()

	s.User = server.NewUser(*targetAddress, accountID)

	// Increment authenticated connections counter
	s.server.authenticatedConnections.Add(1)

	// Log authentication success with standardized format
	// Note: Regular auth via Authenticate() already logs in server.go with cached/method
	// For master SASL auth, we log here with method=master
	if impersonating {
		duration := time.Since(start)
		s.InfoLog("authentication successful", "address", targetAddress.BaseAddress(), "account_id", accountID, "cached", false, "method", "master", "duration", fmt.Sprintf("%.3fs", duration.Seconds()))
	}

	// Track successful authentication
	metrics.AuthenticationAttempts.WithLabelValues("managesieve", s.server.name, s.server.hostname, "success").Inc()
	metrics.AuthenticatedConnectionsCurrent.WithLabelValues("managesieve", s.server.name, s.server.hostname).Inc()
	metrics.CriticalOperationDuration.WithLabelValues("managesieve_authentication").Observe(time.Since(start).Seconds())

	// IMPORTANT: Set authenticated flag AFTER incrementing both counters to prevent race condition
	// If session closes between counter increments and flag setting, cleanup won't decrement
	s.authenticated = true

	// Register connection for tracking
	s.registerConnection(targetAddress.FullAddress())

	// Start termination poller to check for kick commands
	s.startTerminationPoller()

	// Track domain and user connection activity
	if s.User != nil {
		metrics.TrackDomainConnection("managesieve", s.Domain())
		metrics.TrackUserActivity("managesieve", s.FullAddress(), "connection", 1)
	}

	s.sendResponse("OK Authenticated\r\n")
	success = true
	return true
}

// registerConnection registers the connection in the connection tracker
func (s *ManageSieveSession) registerConnection(email string) {
	if s.server.connTracker != nil && s.User != nil {
		// Use configured database query timeout for connection tracking (database INSERT)
		queryTimeout := s.server.rdb.GetQueryTimeout()
		ctx, cancel := context.WithTimeout(s.ctx, queryTimeout)
		defer cancel()

		clientAddr := server.GetAddrString((*s.conn).RemoteAddr())

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

		clientAddr := server.GetAddrString((*s.conn).RemoteAddr())

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

	// Register session for kick notifications and get a channel that closes on kick
	kickChan := s.server.connTracker.RegisterSession(s.AccountID())

	go func() {
		// Unregister when done
		defer s.server.connTracker.UnregisterSession(s.AccountID(), kickChan)

		select {
		case <-kickChan:
			// Kick notification received - close connection
			s.InfoLog("connection kicked, disconnecting")
			(*s.conn).Close()
		case <-s.ctx.Done():
			// Session ended normally
		}
	}()
}

func checkMasterCredential(provided string, actual []byte) bool {
	return subtle.ConstantTimeCompare([]byte(provided), actual) == 1
}
