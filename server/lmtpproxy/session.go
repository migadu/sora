package lmtpproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/proxy"
)

// Session represents an LMTP proxy session.
type Session struct {
	server                *Server
	settings              *reloadableSettings // the server's settings when the session started (see reloadableSettings)
	clientConn            net.Conn            // Reassigned under mu on STARTTLS; shutdown/cancellation snapshot it under mu
	listenerConn          net.Conn            // The accepted connection, never reassigned: its SoraConn carries the JA4 and username, which the TLS conn above it after STARTTLS does not
	startTLSInProgress    bool                // Between the 220 to STARTTLS and the end of its handshake, under mu: the client reads neither plaintext nor, yet, TLS
	greeted               bool                // The 220 greeting has been written, under mu: before it the implicit-TLS handshake may be pending, and a notice written then would wait for it
	closingNoticeSent     bool                // A closing reply (421 notice or 221 QUIT) has claimed the client stream, under mu: nothing may be written after it
	noticeMu              sync.Mutex          // Serializes all client wire writes so async 421 notices never interleave with or precede session replies
	backendConn           net.Conn            // Reassigned under mu on backend connect/STARTTLS/error; shutdown/cancellation snapshot it under mu
	backendRoute          *proxy.BackendRoute // Authorization of the held socket; survives per-recipient routing and transaction resets
	backendReader         *bufio.Reader
	backendWriter         *bufio.Writer
	clientReader          *bufio.Reader
	clientWriter          *bufio.Writer
	sender                string
	mailFromReceived      bool
	to                    string
	toAddress             *server.Address // Parsed recipient address with detail
	username              string
	originalAddress       string // Original base address (cache key) before remotelookup resolution
	isRemoteLookupAccount bool
	routingInfo           *proxy.UserRoutingInfo
	accountID             int64
	serverAddr            string
	routingMethod         string
	sessionID             string // Proxy session ID for end-to-end tracing (also forwarded to the backend)
	clientAddr            string // Cached client address to avoid race with connection close
	clientHelo            string // Client's announced LHLO name, forwarded to the backend via XCLIENT
	releaseConn           func() // Connection limiter cleanup function
	gracefulShutdown      bool   // Set during server shutdown to prevent copy goroutine from closing clientConn
	mu                    sync.Mutex
	ctx                   context.Context
	cancel                context.CancelFunc
	startTime             time.Time
	proxyInfo             *server.ProxyProtocolInfo

	// Connection tracker bookkeeping:
	// LMTP sessions can contain multiple RCPT TO commands (multiple recipients).
	// We register the session as a "connection" against each recipient account the
	// backend accepts a recipient for (forwardRCPT), on a new or an already held
	// backend connection; a refused recipient is not registered.
	// IMPORTANT: s.accountID is overwritten per RCPT; if we only unregister the last one,
	// earlier recipients would leak connection counts permanently. Every accepted
	// account subscribes to kicks, even if counting fails after backend acceptance.
	// Successful counts happen at most once per account; failed counts can retry
	// without creating another kick watcher. close() releases only successful counts.
	registeredAccountIDs map[int64]accountRegistration
	// kickedAccountID is the account whose kick ended the session, 0 if none. It is
	// set by watchKick and logged by close(), on the session goroutine, which owns
	// the fields the session logger reads.
	kickedAccountID atomic.Int64

	// Per-transaction state. The backend's view of a transaction must stay the MTA's:
	// acceptedRcpts counts the recipients the backend accepted (2xx to RCPT), which is
	// also how many end-of-data replies it will send; txPoisoned is set once the backend
	// connection is lost after such an acceptance — from then on every RCPT and DATA of
	// this transaction answers 451 so the MTA retries the whole message, until MAIL,
	// RSET or QUIT (see loseBackend).
	acceptedRcpts int
	txPoisoned    bool
	// backendHasMail records that the held backend accepted the current transaction's
	// MAIL FROM. The proxy answers MAIL itself; a backend is sent it with the first
	// recipient that stays on it (connectToBackend, or the RCPT handler for a backend
	// held from an earlier transaction). Cleared with the rest of the transaction state
	// and when the backend is lost.
	backendHasMail bool

	// smtputf8 marks the current transaction as internationalized (RFC 6531): the MTA
	// gave the SMTPUTF8 MAIL parameter, or sent a non-ASCII address without it. Cleared
	// with the rest of the transaction state.
	smtputf8 bool
	// backendSMTPUTF8 records whether the connected backend advertised SMTPUTF8 in its
	// LHLO reply; the parameter is forwarded only to a backend that did (backendMailFrom).
	backendSMTPUTF8 bool
	// declaredSize is the value of the current transaction's SIZE parameter (RFC 1870),
	// "" when the MTA declared none; backendSIZE records whether the connected backend
	// advertised SIZE, the only kind of backend it is forwarded to (backendMailFrom).
	declaredSize string
	backendSIZE  bool
}

type accountRegistration struct {
	kick    <-chan struct{}
	counted bool
}

// newSession creates a new LMTP proxy session.
func newSession(s *Server, conn net.Conn, proxyInfo *server.ProxyProtocolInfo) *Session {
	sessionCtx, sessionCancel := context.WithCancel(s.ctx)

	// Determine client address (use PROXY protocol info if available)
	clientAddr := server.GetAddrString(conn.RemoteAddr())
	if proxyInfo != nil && proxyInfo.SrcIP != "" {
		clientAddr = proxyInfo.SrcIP
	}

	return &Session{
		server:               s,
		settings:             s.loadSettings(),
		clientConn:           conn,
		listenerConn:         conn,
		clientReader:         bufio.NewReader(conn),
		clientWriter:         bufio.NewWriter(conn),
		clientAddr:           clientAddr, // Use real client IP from PROXY protocol or connection
		ctx:                  sessionCtx,
		cancel:               sessionCancel,
		startTime:            time.Now(),
		proxyInfo:            proxyInfo,
		registeredAccountIDs: make(map[int64]accountRegistration),
		// Generate the session id once, up front, so every log line carries it.
		// It's also forwarded to the backend (XCLIENT), logged there as proxy_session.
		sessionID: idgen.New(),
	}
}

// handleConnection handles the proxy session.
func (s *Session) handleConnection() {
	defer s.cancel()
	defer s.close()
	defer s.server.unregisterSession(s)
	defer metrics.ConnectionsCurrent.WithLabelValues("lmtp_proxy", s.server.name, s.server.hostname).Dec()

	// Ensure connections are closed when context is cancelled (e.g. by absolute timeout or server shutdown)
	// This serves as a fail-safe to unblock reads that don't inherently respect context cancellation.
	// IMPORTANT: The backend connection must be closed here too. Before this, a backend that
	// hung during the handshake or a RCPT/DATA response read kept the session goroutine blocked
	// forever: the absolute session timeout only closed the client connection, which does not
	// unblock a read on the backend connection.
	go func() {
		<-s.ctx.Done()
		s.mu.Lock()
		client, backend := s.clientConn, s.backendConn
		s.mu.Unlock()
		// A TLS close_notify can wait for its peer. Force the transports
		// closed without holding the mutex needed by shutdown and teardown.
		closeSessionTransport(client)
		closeSessionTransport(backend)
	}()

	// Enforce absolute session timeout to prevent hung sessions from leaking
	if s.settings.absoluteSessionTimeout > 0 {
		timeout := time.AfterFunc(s.settings.absoluteSessionTimeout, func() {
			s.InfoLog("Absolute session timeout reached - force closing", "duration", s.settings.absoluteSessionTimeout)
			s.cancel() // Force cancel context to unblock any stuck I/O
		})
		defer timeout.Stop()
	}

	// Log connection at INFO level
	s.InfoLog("connected", "absolute_timeout", s.settings.absoluteSessionTimeout, "auth_idle_timeout", s.server.authIdleTimeout)

	// Register this session for graceful shutdown tracking
	s.server.registerSession(s)

	// Complete the deferred TLS handshake (implicit-TLS listeners). The helper
	// walks the Unwrap() chain, so the handshake runs through the PROXY conn
	// and consumes any ClientHello bytes buffered alongside the PROXY header.
	// Failure is a silent close: no plaintext banner onto a broken TLS stream.
	if _, err := server.PerformDeferredTLSHandshake(s.clientConn); err != nil {
		s.DebugLog("TLS handshake failed", "error", err)
		return
	}

	// Send greeting
	if err := s.sendGreeting(); err != nil {
		s.DebugLog("Failed to send greeting", "error", err)
		return
	}

	// Handle commands until we get RCPT TO
	for {
		// Check if context is cancelled (server shutdown or absolute timeout)
		select {
		case <-s.ctx.Done():
			s.InfoLog("Session context cancelled", "reason", s.ctx.Err())
			s.sendResponse("421 4.3.2 Service closing connection")
			return
		default:
			// Continue normal operation
		}

		// Set a read deadline for the client command to prevent idle connections.
		if s.server.authIdleTimeout > 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.authIdleTimeout)); err != nil {
				s.DebugLog("Failed to set read deadline", "error", err)
				return
			}
		}

		// Read command from client (bounded to prevent pre-auth memory exhaustion)
		line, err := server.ReadBoundedLine(s.clientReader, 8192)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.DebugLog("Client timed out waiting for command")
				s.sendResponse("421 4.4.2 Idle timeout, closing connection")
				return
			}
			if !isClosingError(err) {
				s.DebugLog("Error reading from client", "error", err)
			}
			return
		}

		line = strings.TrimRight(line, "\r\n")
		s.DebugLog("Client command", "line", line)

		// Use the shared command parser. LMTP commands do not have tags.
		_, command, args, err := server.ParseLine(line, false)
		if err != nil {
			s.sendResponse(fmt.Sprintf("500 5.5.2 Syntax error: %s", err.Error()))
			continue
		}

		if command == "" {
			continue // Ignore empty lines
		}

		switch command {
		case "HELO", "EHLO":
			// Not present in LMTP: a server MUST NOT accept them, 500 recommended
			// (RFC 2033 section 4.1), so a client speaking SMTP is detected before
			// it reads per-recipient DATA replies as answers to later commands.
			// Same reply as the backend; no client name is recorded.
			s.sendResponse("500 5.5.1 This is a LMTP server, use LHLO")

		case "LHLO":
			if len(args) < 1 {
				s.sendResponse("501 5.5.4 Syntax error in parameters")
				continue
			}
			// Remember the client's announced name so we can forward it to the backend via
			// XCLIENT (HELO=...); without it the backend's Received: trace falls back to the
			// proxy's own LHLO name. args[0] is a single tokenized field (no spaces/CRLF).
			s.clientHelo = args[0]
			var lhlo strings.Builder
			fmt.Fprintf(&lhlo, "250-%s\r\n", s.server.hostname)

			// Advertise STARTTLS if configured and not already using TLS
			if s.server.tls && s.server.tlsUseStartTLS {
				if _, ok := s.clientConn.(*tls.Conn); !ok {
					lhlo.WriteString("250-STARTTLS\r\n")
				}
			}

			lhlo.WriteString("250-PIPELINING\r\n")
			if s.settings.maxMessageSize > 0 {
				fmt.Fprintf(&lhlo, "250-SIZE %d\r\n", s.settings.maxMessageSize)
			}
			lhlo.WriteString("250-ENHANCEDSTATUSCODES\r\n")
			lhlo.WriteString("250-8BITMIME\r\n")
			// No DSN, as on the backend: neither issues a "delivered" DSN (RFC 3461
			// §5.2.3), so the MTA keeps the duties of §5.2.2 (a "relayed" DSN for
			// NOTIFY=SUCCESS). DSN parameters sent anyway are dropped, not forwarded.
			lhlo.WriteString("250 SMTPUTF8\r\n")
			if _, err := s.writeClientReply(lhlo.String(), false); err != nil {
				return
			}

		case "MAIL":
			fromParam, found := findParameter(args, "FROM:")
			if !found {
				s.sendResponse("501 5.5.4 Syntax error in MAIL command (missing FROM)")
				continue
			}
			// The limit advertised in LHLO is the proxy's own, checked here before the MTA
			// sends the body (RFC 1870 section 6.1): no recipient is routed yet, so no
			// backend is the transaction's. A refused MAIL starts no transaction and
			// leaves the current one alone.
			declaredSize, reply := mailSizeParameter(args, s.settings.maxMessageSize)
			if reply != "" {
				s.InfoLog("MAIL refused for its SIZE parameter", "limit", s.settings.maxMessageSize, "response", reply)
				s.sendResponse(reply)
				continue
			}
			// Note: extractAddress can return an empty string for a null sender "<>", which is valid.
			sender := s.extractAddress(fromParam)
			// A new transaction: whatever became of the previous one is over.
			s.resetTransaction()
			s.sender = sender
			s.mailFromReceived = true
			s.smtputf8 = hasSMTPUTF8Param(args) || !server.IsASCII(sender)
			s.declaredSize = declaredSize
			// Answered here also when a backend is held from an earlier transaction: that
			// backend need not be where any recipient of this one routes, so its answer
			// must not decide the message (its 552 would have the MTA bounce it for every
			// recipient, RFC 1870 section 6.2 (2)). It is sent the MAIL with the first
			// recipient that stays on it (RCPT below), as a new backend is.
			s.sendResponse("250 2.1.0 Ok")

		case "RCPT":
			toParam, found := findParameter(args, "TO:")
			if !found {
				s.DebugLog("RCPT command missing TO parameter", "args", fmt.Sprintf("%v", args))
				s.sendResponse("501 5.5.4 Syntax error in RCPT command (missing TO)")
				continue
			}

			// Extract the recipient address (first part before any parameters)
			// toParam may contain the address and additional ESMTP parameters
			// Example: "<user@example.com> NOTIFY=NEVER ORCPT=rfc822;user@example.com"
			s.DebugLog("Parsing RCPT TO", "toParam", toParam, "args", fmt.Sprintf("%v", args))
			to := s.extractAddress(toParam)
			if to == "" {
				s.DebugLog("Failed to extract address", "toParam", toParam)
				s.sendResponse("501 5.1.3 Bad recipient address syntax")
				continue
			}
			s.DebugLog("Extracted recipient address", "to", to)
			// No MAIL in effect (none yet, RSET, the end of a transaction, or a MAIL the
			// proxy refused while a pipelining MTA sent on): a bad sequence, answered here,
			// as a backend asked would answer 5xx, which reads as a routing inconsistency
			// below.
			if !s.mailFromReceived {
				s.sendResponse("503 5.5.1 Error: need MAIL command")
				continue
			}
			if !server.IsASCII(to) {
				s.smtputf8 = true
			}

			// The backend was lost after it accepted a recipient of this transaction:
			// the MTA must retry the whole message (451). Never 503 — it would bounce
			// the accepted recipients — and never a silent reconnect (see loseBackend).
			if s.txPoisoned || (s.backendConn == nil && s.acceptedRcpts > 0) {
				s.sendResponse("451 4.4.2 Backend connection lost, please retry the transaction")
				continue
			}

			lookupStart := time.Now() // Start account lookup timing
			if err := s.handleRecipient(to, lookupStart); err != nil {
				s.DebugLog("Recipient rejected", "to", to, "error", err)
				// Check if error is due to server shutdown
				if errors.Is(err, server.ErrServerShuttingDown) {
					s.InfoLog("Recipient lookup failed due to server shutdown", "to", to)
					s.sendResponse("421 4.3.2 Service shutting down, please try again later")
					return
				}
				// Check if error is a temporary service unavailability (remotelookup transient error)
				if errors.Is(err, server.ErrAuthServiceUnavailable) {
					s.InfoLog("rejecting recipient - remote lookup service temporarily unavailable",
						"to", to,
						"response", "451 4.4.3")
					s.sendResponse("451 4.4.3 Service temporarily unavailable, please try again later")
					continue
				}
				// Check if error is user not found (permanent failure)
				if errors.Is(err, server.ErrUserNotFound) {
					s.InfoLog("rejecting recipient - user not found",
						"to", to,
						"response", "550 5.1.1")
					s.sendResponse("550 5.1.1 User unknown")
					continue
				}
				// Check if user not found with tempfail response
				if errors.Is(err, server.ErrUserNotFoundTempFail) {
					s.InfoLog("tempfail recipient - user not found (tempfail configured)",
						"to", to,
						"response", "450 4.1.1")
					s.sendResponse("450 4.1.1 User unknown (temporary failure)")
					continue
				}
				// Check if recipient address is syntactically invalid (permanent failure)
				if errors.Is(err, server.ErrInvalidAddress) {
					s.InfoLog("rejecting recipient - invalid address syntax",
						"to", to,
						"error", err.Error(),
						"response", "550 5.1.3")
					s.sendResponse("550 5.1.3 Bad destination mailbox address syntax")
					continue
				}
				// Unknown/unexpected error - use temporary failure to be safe
				// If this is actually a permanent issue, it will keep failing on retry
				// If it's transient (e.g., database timeout), sender can retry
				s.InfoLog("rejecting recipient - unexpected lookup error, temporary failure",
					"to", to,
					"error", err.Error(),
					"response", "451 4.3.0")
				s.sendResponse("451 4.3.0 Temporary failure, please try again later")
				continue
			}

			// Clear the read deadline before connecting to the backend and starting the proxy.
			// The proxy loop will manage its own deadlines.
			if s.server.authIdleTimeout > 0 {
				if err := s.clientConn.SetReadDeadline(time.Time{}); err != nil {
					s.DebugLog("Failed to clear read deadline", "error", err)
				}
			}

			// A numeric destination may have changed pools while this socket stayed
			// open. Keep its original authorization across MAIL/RSET and validate the
			// actual peer before forwarding another recipient. Losing a socket that
			// already accepted recipients poisons the whole transaction.
			if s.backendConn != nil && s.backendRoute != nil {
				if err := s.backendRoute.ValidatePoolDestination(s.backendConn.RemoteAddr().String()); err != nil {
					s.InfoLog("dropping backend connection: route authorization changed", "backend", s.serverAddr, "error", err)
					s.loseBackend()
					if s.txPoisoned {
						s.sendResponse("451 4.4.2 Backend route changed, please retry the transaction")
						continue
					}
				}
			}

			// A session keeps its backend across transactions (an MTA may reuse its LMTP
			// connection), so one held to a backend that has since gone into maintenance
			// is dropped here, at the first recipient of a transaction and before it is
			// sent the MAIL (past refuse_after it refuses every MAIL): the backend holds no
			// accepted recipient yet, so nothing is poisoned, and the connect below routes
			// afresh and sends MAIL FROM. Never later in a transaction.
			if s.backendConn != nil && s.acceptedRcpts == 0 && s.backendInMaintenance() {
				s.InfoLog("dropping backend connection: backend in maintenance", "backend", s.serverAddr)
				s.loseBackend()
			}

			// A held backend must also be where this recipient routes. While the
			// transaction has no accepted recipient, the recipient is routed as on a
			// fresh connection: a held backend it does not route to is dropped (nothing
			// is poisoned) and the connect below reaches the recipient's backend and
			// sends MAIL FROM there. Otherwise an MTA that keeps this connection would get
			// 451 for every transaction whose first recipient lives elsewhere. Once a
			// recipient is accepted the held backend is the transaction's, and one that
			// needs another backend gets 451, to be sent in a new transaction.
			if s.backendConn != nil {
				routeResult, err := proxy.DetermineRoute(proxy.RouteParams{
					Ctx:                   s.ctx,
					Username:              s.originalAddress,
					ClientIP:              server.GetRealClientIP(s.clientConn, s.proxyInfo),
					Protocol:              "lmtp",
					IsRemoteLookupAccount: s.isRemoteLookupAccount,
					RoutingInfo:           s.routingInfo,
					ConnManager:           s.server.connManager,
					EnableAffinity:        s.server.enableAffinity,
					ProxyName:             "LMTP Proxy",
				})

				if err != nil {
					// No pool for this recipient: it cannot share the held backend, whatever
					// pool that backend is in.
					s.InfoLog("rejecting recipient - no backend pool for route", "to", s.to, "error", err)
					s.sendResponse("451 4.3.0 No backend pool for recipient, start new transaction")
					continue
				}
				targetAddr := routeResult.PreferredAddr
				// DetermineRoute can refresh DNS. Recheck the held socket after that
				// refresh too, then compare immutable pool identities rather than
				// accepting equal numeric addresses as proof of compatibility.
				recipientPool := routeResult.Pool
				if targetAddr != "" {
					binding, err := s.server.connManager.BindRoutedBackend(routeResult.RoutingInfo, targetAddr)
					if err != nil {
						s.sendResponse("451 4.3.0 Backend route unavailable, please retry")
						continue
					}
					recipientPool = binding.PoolName()
				}
				mismatch := ""
				if s.backendRoute != nil {
					if err := s.backendRoute.ValidatePoolDestination(s.backendConn.RemoteAddr().String()); err != nil {
						s.loseBackend()
						s.sendResponse("451 4.4.2 Backend route changed, please retry the transaction")
						continue
					}
					if s.backendRoute.PoolName() != recipientPool {
						mismatch = "451 4.3.0 Recipient requires different backend pool, start new transaction"
					}
				}
				// A specific backend (targetAddr) must be the held one. Without one (every
				// member of the pool unhealthy), the held backend still has to be a member of
				// the recipient's pool.
				if mismatch == "" && ((targetAddr != "" && targetAddr != s.serverAddr) ||
					(targetAddr == "" && routeResult.Pool != "" && !s.server.connManager.PoolHasBackend(routeResult.Pool, s.serverAddr))) {
					mismatch = "451 4.3.0 Recipient requires different backend server, start new transaction"
				}
				if mismatch != "" {
					if s.acceptedRcpts > 0 {
						s.InfoLog("rejecting recipient - routing mismatch (requires different backend)",
							"to", s.to,
							"current_backend", s.serverAddr,
							"target_backend", targetAddr,
							"pool", routeResult.Pool,
							"method", routeResult.RoutingMethod)
						s.sendResponse(mismatch)
						continue
					}
					s.InfoLog("dropping backend connection: recipient routes to another backend",
						"to", s.to,
						"backend", s.serverAddr,
						"target_backend", targetAddr,
						"pool", routeResult.Pool,
						"method", routeResult.RoutingMethod)
					s.loseBackend()
				}
			}

			// A held backend this recipient stays on is sent the transaction's MAIL now,
			// as a new backend is on connecting: the MAIL initiates the transaction there
			// (RFC 5321 §4.1.1.2). One that refuses it, or is lost, holds no recipient of
			// this transaction: it is dropped and the connect below asks afresh, so the
			// recipient is answered as on a new connection (552 5.3.4 for a refused size,
			// RFC 1870 section 6.4).
			if s.backendConn != nil && !s.backendHasMail {
				if reply, ok := s.forwardSimpleCommand(s.backendMailFrom()); !ok {
					s.DebugLog("held backend lost on MAIL FROM; reconnecting", "backend", s.serverAddr)
				} else if !strings.HasPrefix(reply, "250") {
					s.InfoLog("dropping backend connection: backend refused MAIL FROM", "backend", s.serverAddr, "response", strings.TrimSpace(reply))
					s.loseBackend()
				} else {
					s.backendHasMail = true
				}
			}

			// Connect to backend if not already connected
			if s.backendConn == nil {
				if err := s.connectToBackend(); err != nil {
					s.InfoLog("backend connection failed", "from", s.sender, "to", s.to, "error", err)
					// The backend refused the declared size: permanent for this recipient
					// (RFC 1870 section 6.4 (2)), not a failed connection to retry.
					if errors.Is(err, errBackendRefusedSize) {
						s.sendResponse("552 5.3.4 Message size exceeds fixed maximum message size")
						continue
					}
					// NOTE: we deliberately do NOT invalidate the lookup cache here.
					// The cache exists to protect remotelookup; invalidating on
					// connect failure would hammer remotelookup with one query per
					// delivery attempt for the whole duration of a backend outage.
					// Routing is revalidated via positive-TTL expiry instead (see
					// integration_tests/lmtpproxy/backend_rejection_cache_test.go).
					s.sendResponse("451 4.4.1 Backend connection failed")
					// Do not return, continue loop to handle RSET or QUIT
					continue
				}
			}

			// Forward RCPT TO to backend
			if s.backendConn != nil {
				s.DebugLog("Forwarding RCPT TO to backend", "to", s.to)
				s.forwardRCPT(line)
			} else {
				s.WarnLog("Cannot forward RCPT - no backend connection", "to", s.to)
				s.sendResponse("451 4.4.1 Backend connection failed")
			}
			// Continue loop to handle subsequent RCPT TOs or DATA

		case "DATA":
			// A backend lost after it accepted a recipient: retry the whole message
			// (451), never 503 — the MTA would bounce the accepted recipients.
			if s.txPoisoned || (s.backendConn == nil && s.acceptedRcpts > 0) {
				s.sendResponse("451 4.4.2 Backend connection lost, please retry the transaction")
				continue
			}
			// No recipient accepted: 503 (RFC 2033 section 4.2), answered here whether or
			// not a backend is held. A held one may lack this transaction's MAIL, or still
			// have an earlier transaction open after a MAIL sent within it.
			if s.acceptedRcpts == 0 {
				s.sendResponse("503 5.5.1 Bad sequence of commands (no valid recipients)")
				continue
			}

			// The backend's answer to DATA is relayed as-is (a hung backend is bounded by
			// readBackendLine's deadline); a backend that fails here is dropped.
			reply, ok := s.forwardSimpleCommand("DATA")
			if !ok {
				s.sendResponse("451 4.4.2 Backend error")
				continue
			}
			if _, err := s.writeClientReply(reply, false); err != nil {
				return
			}
			if !strings.HasPrefix(reply, "354") {
				continue // backend declined DATA; its answer was relayed
			}

			// Relay the body and the per-recipient end-of-data replies inline, then
			// carry on with the next command on this connection: Postfix reuses LMTP
			// connections, and every transaction on one must be routed like the first.
			if !s.relayMessageData() {
				return
			}
			s.resetTransaction()

		case "STARTTLS":
			// Check if STARTTLS is enabled
			if !s.server.tls || !s.server.tlsUseStartTLS {
				s.sendResponse("502 5.5.1 STARTTLS not available")
				continue
			}

			// Check if already using TLS
			if _, ok := s.clientConn.(*tls.Conn); ok {
				s.sendResponse("454 4.3.0 TLS not available: Already using TLS")
				continue
			}

			// Bytes the client sent after STARTTLS were sent in plaintext, where
			// anyone on the path could have added them; the upgraded session must
			// never read them as commands (CVE-2011-0411). They stay plaintext
			// commands instead.
			if s.clientReader.Buffered() > 0 {
				s.sendResponse("503 5.5.1 STARTTLS must be the last command sent before TLS negotiation")
				continue
			}

			// The listener's TLS config, resolved once in New (server.ListenerTLS).
			tlsConfig := s.server.tlsConfig
			if tlsConfig == nil {
				s.DebugLog("STARTTLS config error")
				s.sendResponse("454 4.3.0 TLS not available due to configuration error")
				continue
			}

			// Order a shutdown or kick notice before the reply that makes the client
			// expect TLS, so no plaintext 421 can follow that reply.
			if err := s.beginSTARTTLS(); err != nil {
				s.DebugLog("Failed to send STARTTLS response", "error", err)
				return
			}

			// Upgrade connection to TLS. The handshake records the JA4 on the
			// listener's SoraConn, as an implicit-TLS listener's does.
			tlsConn := tls.Server(s.clientConn, server.StartTLSConfig(tlsConfig, "lmtp_proxy"))
			handshakeCtx, cancelHandshake := context.WithTimeout(s.ctx, startTLSHandshakeTimeout)
			err := tlsConn.HandshakeContext(handshakeCtx)
			cancelHandshake()
			if err != nil {
				s.DebugLog("TLS handshake failed", "error", err)
				return
			}

			// Update session with TLS connection
			s.noticeMu.Lock()
			s.mu.Lock()
			s.clientConn = tlsConn
			s.startTLSInProgress = false
			s.clientReader = bufio.NewReader(tlsConn)
			s.clientWriter = bufio.NewWriter(tlsConn)
			closing := s.closingNoticeSent
			s.mu.Unlock()
			s.noticeMu.Unlock()
			if closing {
				return
			}

			s.DebugLog("STARTTLS negotiation successful")

			// Client must send LHLO again after STARTTLS (RFC 3207)
			// Continue to next iteration to wait for a new LHLO

		case "RSET":
			s.resetTransaction()
			// The backend holds the transaction too (sender, accepted recipients): reset
			// it as well, or the next MAIL/RCPT would land on stale state there. A
			// backend lost here is harmless — the next RCPT reconnects.
			if s.backendConn != nil {
				if _, ok := s.forwardSimpleCommand("RSET"); !ok {
					s.DebugLog("backend lost on RSET; the next recipient reconnects")
				}
			}
			s.sendResponse("250 2.0.0 Ok")

		case "NOOP":
			s.sendResponse("250 2.0.0 Ok")

		case "QUIT":
			s.sendResponse("221 2.0.0 Bye")
			return

		case "VRFY":
			// Every SMTP server MUST support VRFY (RFC 5321 section 4.5.1), and
			// one that does not verify MUST answer 252 (section 7.3), as the
			// backend does.
			s.sendResponse("252 2.5.0 Cannot VRFY user, but will accept message")

		case "EXPN", "HELP", "SEND", "SOML", "SAML", "TURN", "BDAT", "AUTH", "XCLIENT":
			// Known commands the proxy does not implement: 502 (RFC 5321 section
			// 4.2.4). BDAT, AUTH and XCLIENT are the backend's, never advertised
			// here.
			s.sendResponse(fmt.Sprintf("502 5.5.1 %s command not implemented", command))

		default:
			// Not echoed: the verb is whatever the client sent.
			s.sendResponse("500 5.5.2 Syntax error, command unrecognized")
		}
	}
}

var errSessionClosing = errors.New("session closing notice already sent")

// sendGreeting sends the LMTP greeting atomically under noticeMu and marks the
// session greeted unless a closing notice already claimed the connection.
func (s *Session) sendGreeting() error {
	s.noticeMu.Lock()
	defer s.noticeMu.Unlock()
	s.mu.Lock()
	if s.closingNoticeSent {
		s.mu.Unlock()
		return errSessionClosing
	}
	s.mu.Unlock()

	greeting := fmt.Sprintf("220 %s LMTP Service Ready\r\n", s.server.hostname)
	if _, err := s.clientWriter.WriteString(greeting); err != nil {
		return err
	}
	if err := s.clientWriter.Flush(); err != nil {
		return err
	}
	s.mu.Lock()
	s.greeted = true
	s.mu.Unlock()
	return nil
}

// beginSTARTTLS atomically marks STARTTLS in progress and flushes the 220 reply
// under noticeMu unless a closing notice already claimed the connection.
func (s *Session) beginSTARTTLS() error {
	s.noticeMu.Lock()
	defer s.noticeMu.Unlock()
	s.mu.Lock()
	if s.closingNoticeSent {
		s.mu.Unlock()
		return errSessionClosing
	}
	s.startTLSInProgress = true
	s.mu.Unlock()

	if _, err := s.clientWriter.WriteString("220 2.0.0 Ready to start TLS\r\n"); err != nil {
		return err
	}
	return s.clientWriter.Flush()
}

// writeClientReply writes a complete single- or multi-line wire reply (CRLF
// included) to the client under noticeMu, refusing the write once a closing
// reply has claimed the connection. When closing is true, it marks
// closingNoticeSent so later async kick/shutdown notices do not emit another 421.
func (s *Session) writeClientReply(raw string, closing bool) (int, error) {
	s.noticeMu.Lock()
	defer s.noticeMu.Unlock()
	s.mu.Lock()
	if s.closingNoticeSent {
		s.mu.Unlock()
		return 0, errSessionClosing
	}
	if closing {
		s.closingNoticeSent = true
	}
	s.mu.Unlock()

	n, err := s.clientWriter.WriteString(raw)
	if err != nil {
		return n, err
	}
	if err := s.clientWriter.Flush(); err != nil {
		return n, err
	}
	return n, nil
}

// sendResponse sends a response to the client.
func (s *Session) sendResponse(response string) error {
	closing := strings.HasPrefix(response, "421 ") || response == "421" ||
		strings.HasPrefix(response, "221 ") || response == "221"
	_, err := s.writeClientReply(response+"\r\n", closing)
	return err
}

// Log logs a client command if debug is enabled.
// This is for debug output only, not session logging.
func (s *Session) Log(format string, args ...any) {
	if s.server.debugWriter != nil {
		message := fmt.Sprintf(format, args...)
		s.server.debugWriter.Write([]byte(message))
	}
}

// startTLSHandshakeTimeout bounds the handshake after STARTTLS, as SoraTLSConn
// bounds an implicit-TLS one.
const startTLSHandshakeTimeout = 10 * time.Second

// acceptedConn returns the connection the listener accepted. A Session built
// without newSession (as tests do) has only its clientConn.
func (s *Session) acceptedConn() net.Conn {
	if s.listenerConn != nil {
		return s.listenerConn
	}
	return s.clientConn
}

// getLogger returns a ProxySessionLogger for this session
func (s *Session) getLogger() *server.ProxySessionLogger {
	return &server.ProxySessionLogger{
		Protocol:   "lmtp_proxy",
		ServerName: s.server.name,
		ClientConn: s.acceptedConn(),
		Username:   s.username,
		AccountID:  s.accountID,
		SessionID:  s.sessionID,
		Debug:      s.server.loadSettings().debug,
	}
}

// InfoLog logs at INFO level with session context
func (s *Session) InfoLog(msg string, keyvals ...any) {
	s.getLogger().InfoLog(msg, keyvals...)
}

// DebugLog logs at DEBUG level with session context
func (s *Session) DebugLog(msg string, keyvals ...any) {
	s.getLogger().DebugLog(msg, keyvals...)
}

// WarnLog logs at WARN level with session context
func (s *Session) WarnLog(msg string, keyvals ...any) {
	s.getLogger().WarnLog(msg, keyvals...)
}

// ErrorLog logs at ERROR level with session context
func (s *Session) ErrorLog(msg string, keyvals ...any) {
	s.getLogger().ErrorLog(msg, keyvals...)
}

// stripUnsupportedRCPTParameters removes ESMTP parameters from RCPT TO commands that
// are not commonly supported by LMTP servers. This uses an allowlist approach - only
// explicitly allowed parameters are kept, everything else is stripped.
//
// Allowed RCPT TO parameters for LMTP:
//   - XRCPTFORWARD: Dovecot-specific forwarding information (original recipient)
//
// Stripped parameters:
//   - NOTIFY, ORCPT: DSN (RFC 3461 §4.1, §4.2), which neither the proxy nor the
//     backend announces; an MTA should not send them, but some do. RET and ENVID,
//     the DSN parameters of MAIL (§4.3, §4.4), are dropped by backendMailFrom.
//   - Any other unknown ESMTP parameters
//
// Examples:
//   - "RCPT TO:<user@example.com> NOTIFY=NEVER" -> "RCPT TO:<user@example.com>"
//   - "RCPT TO:<user@example.com> NOTIFY=NEVER XRCPTFORWARD=fwd@example.com" -> "RCPT TO:<user@example.com> XRCPTFORWARD=fwd@example.com"
//   - "RCPT TO:<user@example.com> UNKNOWN=value" -> "RCPT TO:<user@example.com>"
func stripUnsupportedRCPTParameters(command string) string {
	// Only process RCPT TO commands
	if !strings.HasPrefix(strings.ToUpper(command), "RCPT TO") {
		return command
	}

	// Find the recipient address (between < and >)
	startIdx := strings.Index(command, "<")
	if startIdx == -1 {
		return command // No angle bracket, return as-is
	}

	endIdx := strings.Index(command[startIdx:], ">")
	if endIdx == -1 {
		return command // No closing bracket, return as-is
	}
	endIdx += startIdx // Adjust to absolute position

	// Extract the RCPT TO prefix and the address
	// Everything before and including the closing > bracket
	cleanCommand := command[:endIdx+1]

	// Check if there are any parameters after the address
	remainder := strings.TrimSpace(command[endIdx+1:])
	if remainder == "" {
		return cleanCommand // No parameters, already clean
	}

	// Allowlist of RCPT TO parameters supported by LMTP servers
	// Using a map for O(1) lookup
	allowedParams := map[string]bool{
		"XRCPTFORWARD": true, // Dovecot-specific: original recipient for forwarding
		// Add more LMTP-supported parameters here if needed
	}

	// Parse parameters and keep only allowed ones
	params := strings.Fields(remainder)
	var keptParams []string

	for _, param := range params {
		// Extract parameter name (before '=')
		parts := strings.SplitN(param, "=", 2)
		if len(parts) == 0 {
			continue // Malformed parameter
		}

		paramName := strings.ToUpper(parts[0])

		// Keep only if in allowlist
		if allowedParams[paramName] {
			keptParams = append(keptParams, param)
		}
		// Silently drop everything else (DSN parameters, unknown parameters, etc.)
	}

	// Reconstruct command with kept parameters
	if len(keptParams) > 0 {
		return cleanCommand + " " + strings.Join(keptParams, " ")
	}

	return cleanCommand
}

// extractAddress extracts email address from MAIL FROM or RCPT TO parameter.
// This handles ESMTP parameters that may follow the address, such as:
//   - MAIL FROM:<user@example.com> SIZE=1234
//   - RCPT TO:<user@example.com> NOTIFY=NEVER ORCPT=rfc822;user@example.com
func (s *Session) extractAddress(param string) string {
	// The parameter value might be quoted, so unquote it first.
	param = server.UnquoteString(strings.TrimSpace(param))

	if len(param) < 2 {
		return ""
	}

	// Handle <address> format with or without additional ESMTP parameters
	// Extract everything between < and > (the address), ignoring anything after >
	if param[0] == '<' {
		endIdx := strings.Index(param, ">")
		if endIdx > 0 {
			// Found closing bracket - extract address between < and >
			return param[1:endIdx]
		}
		// No closing bracket found - invalid format
		return ""
	}

	// Some clients might not use angle brackets (non-standard but handle it)
	// In this case, stop at the first space (which would separate address from parameters)
	if idx := strings.Index(param, " "); idx > 0 {
		return param[:idx]
	}

	return param
}

// handleRecipient looks up the recipient, determines routing, and sets session state.
func (s *Session) handleRecipient(to string, lookupStart time.Time) error {
	address, err := server.NewAddress(to)
	if err != nil {
		s.InfoLog("rejecting recipient - invalid address format",
			"to", to,
			"error", err.Error())
		return fmt.Errorf("%w: %w", server.ErrInvalidAddress, err)
	}

	s.to = to
	s.toAddress = &address // Store parsed address with detail
	s.username = address.BaseAddress()

	// Store original submitted address for cache operations
	// Cache key must always be the original address, not resolved address
	originalAddress := s.username
	s.originalAddress = originalAddress // Store in session for cache invalidation later

	// Set username on client connection for timeout logging
	if soraConn, ok := s.acceptedConn().(interface{ SetUsername(string) }); ok {
		soraConn.SetUsername(s.username)
	}

	// Check cache first (for routing info - no password validation needed)
	if cached, found := s.server.lookupCache.Get(s.server.name, originalAddress); found {
		if cached.IsNegative {
			// User previously not found - return cached failure
			// Note: Do NOT refresh negative entries - let them expire naturally so we can
			// re-check the database in case the user was created since last check
			metrics.LookupCacheResults.WithLabelValues("lmtp_proxy", "hit_negative").Inc()

			// Single consolidated log for lookup failure
			duration := time.Since(lookupStart)
			s.InfoLog("account lookup failed",
				"address", s.username,
				"reason", "user_not_found",
				"cached", true,
				"method", "cache",
				"duration", fmt.Sprintf("%.3fs", duration.Seconds()))

			// The reply a fresh lookup from the same source gives now: a remote
			// lookup negative gets the reply its 404 got, a database negative is
			// still deferred while no default-pool backend is healthy.
			return s.userNotFoundError(cached.FromRemoteLookup)
		} else {
			// User found - use cached routing info
			metrics.LookupCacheResults.WithLabelValues("lmtp_proxy", "hit").Inc()

			s.accountID = cached.AccountID
			s.isRemoteLookupAccount = cached.FromRemoteLookup
			// Rebuilt exactly as the uncached login routed (proxy.RouteFromCache): the pin,
			// its enforcement and every backend-leg setting the lookup answer carried.
			s.routingInfo = proxy.RouteFromCache(cached)

			if cached.ActualEmail != "" {
				s.username = cached.ActualEmail
			}

			// NOTE: We intentionally do NOT call Refresh() for routing cache.
			// Routing entries should expire after positive_ttl to allow periodic
			// revalidation via remotelookup. This ensures that when a domain moves
			// backends, active users eventually pick up the new backend.
			// See: integration_tests/lmtpproxy/routing_cache_expiration_test.go

			// Single consolidated log for lookup success
			duration := time.Since(lookupStart)
			s.InfoLog("account lookup successful",
				"address", s.username,
				"cached", true,
				"method", "cache",
				"duration", fmt.Sprintf("%.3fs", duration.Seconds()))

			return nil
		}
	} else if s.server.lookupCache != nil {
		// A disabled cache (nil) reads nothing and counts nothing.
		metrics.LookupCacheResults.WithLabelValues("lmtp_proxy", "miss").Inc()
	}

	// 1. Try remotelookup first
	hasRouting := s.server.connManager.HasRouting()

	if hasRouting {
		// Call remotelookup API
		routingTimeout := s.server.connManager.GetRemoteLookupTimeout()
		routingCtx, routingCancel := context.WithTimeout(s.ctx, routingTimeout)
		defer routingCancel()

		remoteLookupStart := time.Now()
		// $ip is the delivering MTA: this proxy's client, the PROXY header source when
		// there is one (the address XCLIENT forwards to the backend as well).
		routingInfo, lookupErr := s.server.connManager.LookupUserRoute(routingCtx, s.username, server.GetRealClientIP(s.clientConn, s.proxyInfo))
		remoteLookupDuration := time.Since(remoteLookupStart).Seconds()
		// 401/403: the lookup refused the account, a verdict and no route (handled below).
		refused := errors.Is(lookupErr, proxy.ErrRemoteLookupRefused)

		if lookupErr != nil && !refused {
			s.InfoLog("remotelookup failed", "username", s.username, "error", lookupErr, "cache", "miss")

			// Check if error is due to context cancellation (server shutdown)
			if errors.Is(lookupErr, server.ErrServerShuttingDown) {
				s.InfoLog("remotelookup cancelled due to server shutdown")
				metrics.RemoteLookupResult.WithLabelValues("lmtp", "shutdown").Inc()
				metrics.RemoteLookupDuration.WithLabelValues("lmtp", "shutdown").Observe(remoteLookupDuration)
				return server.ErrServerShuttingDown
			}

			// Transient errors (network, 5xx, circuit breaker) - NEVER fallback to DB
			// These are service availability issues, not "user not found" cases
			// Return ErrAuthServiceUnavailable so caller can send 451 (temporary) instead of 550 (permanent)
			duration := time.Since(lookupStart)
			s.InfoLog("remotelookup transient error - service unavailable, rejecting recipient",
				"username", s.username,
				"error", lookupErr.Error(),
				"duration", fmt.Sprintf("%.3fs", duration.Seconds()))
			metrics.RemoteLookupResult.WithLabelValues("lmtp", "transient_error_rejected").Inc()
			metrics.RemoteLookupDuration.WithLabelValues("lmtp", "transient_error").Observe(remoteLookupDuration)
			return server.ErrAuthServiceUnavailable
		} else if routingInfo != nil {
			// RemoteLookup succeeded - may or may not have ServerAddress
			// If no ServerAddress, backend selection will use consistent hash/round-robin
			metrics.RemoteLookupResult.WithLabelValues("lmtp", "success").Inc()
			metrics.RemoteLookupDuration.WithLabelValues("lmtp", "success").Observe(remoteLookupDuration)
			s.routingInfo = routingInfo
			s.isRemoteLookupAccount = true
			s.accountID = routingInfo.AccountID // May be 0, that's fine

			// Use ActualEmail from remotelookup if available (for token resolution)
			var resolvedEmail string
			if routingInfo.ActualEmail != "" {
				resolvedEmail = routingInfo.ActualEmail
				s.username = resolvedEmail // Update username with resolved email
			} else {
				resolvedEmail = s.username // Use already-set username (BaseAddress)
			}

			// Cache positive result (routing info found)
			// Cache key is originalAddress (BaseAddress of submitted recipient)
			// Store ActualEmail if remotelookup resolved to a different address
			entry := &lookupcache.CacheEntry{
				ActualEmail: resolvedEmail, // Store resolved email for cache hits
				Result:      lookupcache.AuthSuccess,
			}
			proxy.CacheRoute(entry, routingInfo) // the route, its settings, FromRemoteLookup
			s.server.lookupCache.Set(s.server.name, originalAddress, entry)

			// Single consolidated log for lookup success
			duration := time.Since(lookupStart)
			s.InfoLog("account lookup successful",
				"address", s.username,
				"cached", false,
				"method", "remotelookup",
				"duration", fmt.Sprintf("%.3fs", duration.Seconds()))

			return nil
		} else {
			// No route: the user is not found in remotelookup (404/3xx or empty response),
			// or the account is refused (401/403). lookup_local_users applies to the first
			// only: a refused recipient is never looked up, and delivered, in the local
			// database.
			duration := time.Since(lookupStart)
			outcome := "user_not_found"
			if refused {
				outcome = "refused"
			}
			metrics.RemoteLookupDuration.WithLabelValues("lmtp", outcome).Observe(remoteLookupDuration)
			if !refused && s.server.remotelookupConfig != nil && s.server.remotelookupConfig.ShouldLookupLocalUsers() {
				s.InfoLog("user not found in remote lookup, local lookup enabled - attempting main DB",
					"username", s.username,
					"duration", fmt.Sprintf("%.3fs", duration.Seconds()))
				metrics.RemoteLookupResult.WithLabelValues("lmtp", "user_not_found_fallback").Inc()
				// Fallthrough to main DB
			} else {
				// No database fallback - use configured response
				response := "reject" // default
				if s.server.remotelookupConfig != nil {
					response = s.server.remotelookupConfig.GetUserNotFoundResponse()
				}

				msg := "user not found in remote lookup, fallback disabled"
				if refused {
					msg = "account refused by remote lookup (401/403), no fallback"
				}
				s.InfoLog(msg,
					"username", s.username,
					"duration", fmt.Sprintf("%.3fs", duration.Seconds()),
					"response", response)
				metrics.RemoteLookupResult.WithLabelValues("lmtp", outcome+"_"+response).Inc()

				// Cache negative result to protect remotelookup. FromRemoteLookup lets a
				// cache hit give the reply given here (userNotFoundError).
				s.server.lookupCache.Set(s.server.name, originalAddress, &lookupcache.CacheEntry{
					Result:           lookupcache.AuthUserNotFound,
					IsNegative:       true,
					FromRemoteLookup: true,
				})

				return s.userNotFoundError(true)
			}
		}
	} else {
		s.InfoLog("remotelookup not available - HasRouting returned false", "username", s.username)
	}

	// 2. Fallback to main DB to get account ID for affinity
	s.isRemoteLookupAccount = false

	// Skip database lookup if database is not available (proxy-only mode)
	if s.server.rdb == nil {
		return fmt.Errorf("database not available for account lookup in proxy-only mode")
	}

	// Use configured database query timeout instead of hardcoded value
	queryTimeout := s.server.rdb.GetQueryTimeout()
	dbCtx, dbCancel := context.WithTimeout(s.ctx, queryTimeout)
	defer dbCancel()

	// Use GetActiveAccountIDByAddressWithRetry which properly handles ErrUserNotFound
	// as a business logic error (not a circuit breaker failure)
	accountID, err := s.server.rdb.GetActiveAccountIDByAddressWithRetry(dbCtx, s.username)
	if err != nil {
		// Check if error is due to session context cancellation (server shutdown)
		// Note: Must check s.ctx.Err(), not just the query error, because the query context
		// can timeout (DeadlineExceeded) independently from server shutdown
		if s.ctx.Err() != nil {
			s.InfoLog("database lookup cancelled due to server shutdown")
			return server.ErrServerShuttingDown
		}

		// Check if user was not found (business logic error, not a system failure)
		if errors.Is(err, consts.ErrUserNotFound) {
			// IMPORTANT: Before permanently rejecting (550), check if backends are healthy.
			// If all backends are down, we can't verify if user exists on backends, so return tempfail.
			// This prevents wrongly bouncing messages when:
			//  - Proxy has a separate/lagging database instance
			//  - User exists on backends but not on proxy's database
			//  - Backends are temporarily unavailable
			if !s.server.connManager.HasHealthyPoolBackends() {
				s.WarnLog("user not found in proxy database, but all backends unhealthy - returning tempfail to allow retry",
					"address", s.username)
				return server.ErrUserNotFoundTempFail
			}

			// Cache negative result (user not found)
			// We reached here so user is not in remotelookup (if enabled) AND not in DB.
			s.server.lookupCache.Set(s.server.name, originalAddress, &lookupcache.CacheEntry{
				Result:     lookupcache.AuthUserNotFound,
				IsNegative: true,
			})

			// Single consolidated log for lookup failure
			duration := time.Since(lookupStart)
			s.InfoLog("account lookup failed",
				"address", s.username,
				"reason", "user_not_found",
				"cached", false,
				"method", "main_db",
				"negative_cache_skipped", false,
				"duration", fmt.Sprintf("%.3fs", duration.Seconds()))

			return server.ErrUserNotFound
		}

		// Other database errors (timeouts, connection failures, etc.)
		s.WarnLog("database lookup error", "address", s.username, "error", err)
		return fmt.Errorf("database lookup error: %w", err)
	}

	s.accountID = accountID

	// Set routing info so connectToBackend doesn't call remotelookup again
	// Preserve global proxy settings (XCLIENT support) since we're not using remotelookup routing
	s.routingInfo = &proxy.UserRoutingInfo{
		AccountID:        s.accountID,
		RemoteUseXCLIENT: s.server.remoteUseXCLIENT,
	}

	// Cache positive result (routing info from DB)
	s.server.lookupCache.Set(s.server.name, originalAddress, &lookupcache.CacheEntry{
		AccountID:        s.accountID,
		RemoteUseXCLIENT: s.server.remoteUseXCLIENT,
		Result:           lookupcache.AuthSuccess,
		FromRemoteLookup: false,
	})

	// Single consolidated log for lookup success
	duration := time.Since(lookupStart)
	s.InfoLog("account lookup successful",
		"address", s.username,
		"cached", false,
		"method", "main_db",
		"duration", float64(int(duration.Seconds()*1000))/1000)

	return nil
}

// connectToBackend establishes a connection to the backend server. When it fails, the
// session holds no backend connection.
func (s *Session) connectToBackend() (err error) {
	routeResult, err := proxy.DetermineRoute(proxy.RouteParams{
		Ctx:                   s.ctx,
		Username:              s.originalAddress, // Use original address (not resolved address) for route/affinity consistency
		ClientIP:              server.GetRealClientIP(s.clientConn, s.proxyInfo),
		Protocol:              "lmtp",
		IsRemoteLookupAccount: s.isRemoteLookupAccount,
		RoutingInfo:           s.routingInfo,
		ConnManager:           s.server.connManager,
		EnableAffinity:        s.server.enableAffinity,
		ProxyName:             "LMTP Proxy",
	})
	if err != nil {
		// No pool to route into (a pool this proxy lacks, or none named and none default):
		// fail the connection rather than let the fallback dial another pool's backend.
		return fmt.Errorf("failed to determine route: %w", err)
	}

	// Update session routing info if it was fetched by DetermineRoute
	s.routingInfo = routeResult.RoutingInfo
	s.routingMethod = routeResult.RoutingMethod
	preferredAddr := routeResult.PreferredAddr
	isRemoteLookupRoute := routeResult.IsRemoteLookupRoute

	s.DebugLog("Routing", "method", routeResult.RoutingMethod, "preferred_addr", preferredAddr, "is_remotelookup", isRemoteLookupRoute)
	if s.routingInfo != nil {
		s.DebugLog("Routing info", "server", s.routingInfo.ServerAddress, "tls", s.routingInfo.RemoteTLS, "starttls", s.routingInfo.RemoteTLSUseStartTLS, "tls_verify", s.routingInfo.RemoteTLSVerify, "xclient", s.routingInfo.RemoteUseXCLIENT)
	}

	// 4. Connect using the determined address (or round-robin if empty)
	// Track which routing method was used for this connection.
	metrics.ProxyRoutingMethod.WithLabelValues("lmtp", routeResult.RoutingMethod).Inc()

	// The backend's PROXY header names the real client (the incoming PROXY header's source).
	clientHost, clientPort := server.GetRealClientAddr(s.clientConn, s.proxyInfo)
	serverHost, serverPort := server.GetHostPortFromAddr(s.clientConn.LocalAddr())
	var backendRoute *proxy.BackendRoute
	if preferredAddr != "" {
		backendRoute, err = s.server.connManager.BindRoutedBackend(s.routingInfo, preferredAddr)
		if err != nil {
			return fmt.Errorf("failed to bind backend route: %w", err)
		}
	}
	backendConn, actualAddr, err := s.server.connManager.ConnectWithProxy(
		s.ctx,
		preferredAddr,
		clientHost, clientPort, serverHost, serverPort, s.routingInfo,
	)
	if err != nil {
		// Track backend connection failure
		metrics.ProxyBackendConnections.WithLabelValues("lmtp", "failure").Inc()
		return fmt.Errorf("failed to connect to backend: %w", err)
	}

	if isRemoteLookupRoute && actualAddr != preferredAddr {
		// The remotelookup route specified a server, but we connected to a different one.
		// This means the preferred server failed and the connection manager fell back.
		// For remotelookup routes, this is a hard failure.
		backendConn.Close()
		metrics.ProxyBackendConnections.WithLabelValues("lmtp", "failure").Inc()
		return fmt.Errorf("remotelookup route to %s failed, and fallback is disabled for remotelookup routes", preferredAddr)
	}

	// With no preferred destination, round-robin selected the actual member.
	// The route still carries its expected pool, so a post-dial ownership change
	// fails closed instead of reclassifying this socket into another pool.
	if backendRoute == nil {
		backendRoute, err = s.server.connManager.BindRoutedBackend(s.routingInfo, actualAddr)
	}
	if err == nil {
		err = backendRoute.ValidateDestination(backendConn.RemoteAddr().String())
	}
	if err != nil {
		backendConn.Close()
		return fmt.Errorf("backend route changed while connecting: %w", err)
	}

	// Track backend connection success
	metrics.ProxyBackendConnections.WithLabelValues("lmtp", "success").Inc()
	s.mu.Lock()
	s.backendConn = backendConn
	s.backendRoute = backendRoute
	s.backendReader = bufio.NewReader(backendConn)
	s.backendWriter = bufio.NewWriter(backendConn)
	s.mu.Unlock()
	s.serverAddr = actualAddr
	// From here on the session holds the connection, so a failure drops it (closed and
	// cleared), or the next command would go to the closed connection instead of
	// connecting afresh.
	defer func() {
		if err != nil {
			s.loseBackend()
		}
	}()

	// Enable TCP keepalive on backend connection to detect dead connections
	// This helps detect network partitions and stale connections without waiting for read timeout
	if tcpConn, ok := backendConn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			s.DebugLog("Failed to enable TCP keepalive on backend", "error", err)
		} else if err := tcpConn.SetKeepAlivePeriod(2 * time.Minute); err != nil {
			s.DebugLog("Failed to set TCP keepalive period on backend", "error", err)
		}
	}

	// Record successful connection for future affinity
	// Auth-only remotelookup users (IsRemoteLookupAccount=true but ServerAddress="") should get affinity
	// Use s.originalAddress for affinity key to ensure stability across resolutions
	if s.server.enableAffinity && actualAddr != "" {
		proxy.UpdateAffinityAfterConnection(proxy.RouteParams{
			Username:              s.originalAddress,
			Protocol:              "lmtp",
			IsRemoteLookupAccount: s.isRemoteLookupAccount,
			RoutingInfo:           s.routingInfo, // Pass routing info so UpdateAffinity can check ServerAddress
			ConnManager:           s.server.connManager,
			EnableAffinity:        s.server.enableAffinity,
			ProxyName:             "LMTP Proxy",
		}, actualAddr, routeResult.RoutingMethod == "affinity")
	}

	// Read greeting from backend (bounded, with read deadline: a backend that
	// accepts TCP but never sends its greeting must not hang the session)
	greeting, err := s.readBackendLine()
	if err != nil {
		return fmt.Errorf("failed to read backend greeting: %w", err)
	}
	if !strings.HasPrefix(greeting, "220") {
		return fmt.Errorf("unexpected backend greeting: %q", strings.TrimSpace(greeting))
	}

	// Send LHLO to backend
	lhloCmd := fmt.Sprintf("LHLO %s\r\n", s.server.hostname)
	_, err = s.backendWriter.WriteString(lhloCmd)
	if err != nil {
		return fmt.Errorf("failed to send LHLO: %w", err)
	}
	s.backendWriter.Flush()

	// Read LHLO response (bounded lines and line count so a misbehaving backend
	// cannot keep us in this loop or grow memory without limit)
	s.backendSMTPUTF8, s.backendSIZE = false, false
	for lines := 0; ; lines++ {
		if lines >= maxLHLOResponseLines {
			return fmt.Errorf("backend LHLO response exceeded %d lines", maxLHLOResponseLines)
		}
		response, err := s.readBackendLine()
		if err != nil {
			return fmt.Errorf("failed to read LHLO response: %w", err)
		}

		s.DebugLog("Backend LHLO response", "response", strings.TrimRight(response, "\r"))
		if isSMTPUTF8Capability(response) {
			s.backendSMTPUTF8 = true
		}
		if isSIZECapability(response) {
			s.backendSIZE = true
		}

		// Check if this is the last line (no hyphen after status code)
		if len(response) >= 4 && response[3] != '-' {
			if !strings.HasPrefix(response, "250") {
				return fmt.Errorf("backend LHLO failed: %s", response)
			}
			break
		}
	}

	// remote_tls_use_starttls: the connection manager dialed plaintext and left the upgrade
	// to us. Whether this connection needs it is asked of the settings the dial used
	// (the route's or the proxy's own), so the two cannot disagree.
	if tlsConfig := s.server.connManager.BackendStartTLSConfig(s.routingInfo, actualAddr, s.backendConn); tlsConfig != nil {
		s.DebugLog("Negotiating StartTLS with backend", "backend", actualAddr, "insecure_skip_verify", tlsConfig.InsecureSkipVerify)

		// Send STARTTLS command
		_, err := s.backendWriter.WriteString("STARTTLS\r\n")
		if err != nil {
			return fmt.Errorf("failed to send STARTTLS command: %w", err)
		}
		s.backendWriter.Flush()

		// Read STARTTLS response (bounded, with read deadline)
		response, err := s.readBackendLine()
		if err != nil {
			return fmt.Errorf("failed to read STARTTLS response: %w", err)
		}

		if !strings.HasPrefix(strings.TrimSpace(response), "220") {
			return fmt.Errorf("backend STARTTLS failed: %s", strings.TrimSpace(response))
		}

		// Bytes already buffered came in plaintext after the 220, where anyone on the path
		// could have put them. The reader replaced below would drop them; a stream that
		// broke the protocol there fails the connection instead (cf. CVE-2011-0411).
		if s.backendReader.Buffered() > 0 {
			return errors.New("backend sent data after its STARTTLS response")
		}

		// Upgrade connection to TLS. readBackendLine cleared its deadline, so the
		// handshake gets its own: a backend that never answers must not hold the session.
		if timeout := s.server.connManager.GetConnectTimeout(); timeout > 0 {
			if err := s.backendConn.SetDeadline(time.Now().Add(timeout)); err != nil {
				return fmt.Errorf("failed to set the STARTTLS handshake deadline: %w", err)
			}
		}
		tlsConn := tls.Client(s.backendConn, tlsConfig)
		err = tlsConn.Handshake()
		if err != nil {
			return fmt.Errorf("TLS handshake with backend failed: %w", err)
		}
		if err := tlsConn.SetDeadline(time.Time{}); err != nil {
			return fmt.Errorf("failed to clear the STARTTLS handshake deadline: %w", err)
		}

		s.DebugLog("StartTLS negotiation successful with backend", "backend", actualAddr)
		s.mu.Lock()
		s.backendConn = tlsConn
		s.backendReader = bufio.NewReader(tlsConn)
		s.backendWriter = bufio.NewWriter(tlsConn)
		s.mu.Unlock()

		// After STARTTLS, we need to send LHLO again
		lhloCmd := fmt.Sprintf("LHLO %s\r\n", s.server.hostname)
		_, err = s.backendWriter.WriteString(lhloCmd)
		if err != nil {
			return fmt.Errorf("failed to send LHLO after STARTTLS: %w", err)
		}
		s.backendWriter.Flush()

		// Read LHLO response again (bounded lines and line count)
		s.backendSMTPUTF8, s.backendSIZE = false, false
		for lines := 0; ; lines++ {
			if lines >= maxLHLOResponseLines {
				return fmt.Errorf("backend LHLO response after STARTTLS exceeded %d lines", maxLHLOResponseLines)
			}
			response, err := s.readBackendLine()
			if err != nil {
				return fmt.Errorf("failed to read LHLO response after STARTTLS: %w", err)
			}

			s.DebugLog("Backend LHLO response after STARTTLS", "response", strings.TrimRight(response, "\r"))
			if isSMTPUTF8Capability(response) {
				s.backendSMTPUTF8 = true
			}
			if isSIZECapability(response) {
				s.backendSIZE = true
			}

			// Check if this is the last line
			if len(response) >= 4 && response[3] != '-' {
				if !strings.HasPrefix(response, "250") {
					return fmt.Errorf("backend LHLO after STARTTLS failed: %s", response)
				}
				break
			}
		}
	}

	// Send forwarding parameters via XCLIENT if enabled
	useXCLIENT := s.server.remoteUseXCLIENT
	// The route's setting applies to the backend the lookup named or its pool picked (as for the dial)
	if s.routingInfo.UsesRouteSettings(s.serverAddr) {
		useXCLIENT = s.routingInfo.RemoteUseXCLIENT
	}
	// The proxy's role is to forward the original client's information if enabled.
	// It is the backend server's responsibility to verify if the connection
	// (from this proxy) is from a trusted IP before processing forwarded parameters.
	// The `isFromTrustedProxy()` check is for proxy-chaining, where a backend
	// needs to validate if the client connecting to it is another trusted proxy.
	if useXCLIENT {
		if err := s.sendForwardingParametersToBackend(s.backendWriter, s.backendReader); errors.Is(err, errXCLIENTRefused) {
			s.WarnLog("Failed to send XCLIENT to backend - continuing without forwarding parameters", "backend", s.serverAddr, "error", err)
			// Continue without forwarding parameters rather than failing: the refusal
			// ended the exchange.
			// Note: If XCLIENT is rejected, this may indicate backend is not configured
			// to accept XCLIENT from this proxy IP (check backend's trusted_networks)
		} else if err != nil {
			// A reply of the exchange was not read (a write or read error, or the
			// deadline). It may still come, and MAIL FROM would read it as its own.
			return fmt.Errorf("XCLIENT exchange with backend: %w", err)
		}
	}

	// Send MAIL FROM to backend
	if s.mailFromReceived {
		mailCmd := s.backendMailFrom() + "\r\n"
		_, err = s.backendWriter.WriteString(mailCmd)
		if err != nil {
			return fmt.Errorf("failed to send MAIL FROM: %w", err)
		}
		s.backendWriter.Flush()

		// Read MAIL FROM response (bounded, with read deadline)
		response, err := s.readBackendLine()
		if err != nil {
			return fmt.Errorf("failed to read MAIL FROM response: %w", err)
		}

		if !strings.HasPrefix(response, "250") {
			if strings.HasPrefix(response, "552") {
				return fmt.Errorf("%w: %s", errBackendRefusedSize, strings.TrimSpace(response))
			}
			return fmt.Errorf("backend MAIL FROM failed: %s", response)
		}

		s.DebugLog("Backend MAIL FROM accepted")
		s.backendHasMail = true
	}

	return nil
}

// backendResponseLineMax bounds a single backend response line during the
// handshake and per-command phases. RFC 5321 reply lines are far below this.
const backendResponseLineMax = 4096

// maxLHLOResponseLines bounds multiline LHLO responses so a misbehaving
// backend cannot keep the proxy in the reply loop forever.
const maxLHLOResponseLines = 64

// readBackendLine reads one bounded response line from the backend with a
// read deadline (the backend connect timeout). The deadline is cleared after
// the read so later phases (the relay loop manages its own deadlines) are
// unaffected. Without this, a backend that accepted the connection but then
// went silent kept the session goroutine blocked forever.
func (s *Session) readBackendLine() (string, error) {
	timeout := s.server.connManager.GetConnectTimeout()
	if timeout > 0 {
		if err := s.backendConn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return "", fmt.Errorf("failed to set backend read deadline: %w", err)
		}
		defer func() {
			if err := s.backendConn.SetReadDeadline(time.Time{}); err != nil {
				s.DebugLog("failed to clear backend read deadline", "error", err)
			}
		}()
	}
	return server.ReadBoundedLine(s.backendReader, backendResponseLineMax)
}

// invalidateLookupCache removes the cached routing entry for the originally
// submitted recipient address. The cache key must be the SUBMITTED address
// (s.originalAddress), not the resolved one (s.username), because that is the
// key handleRecipient used for Set.
func (s *Session) invalidateLookupCache(reason string) {
	if s.server.lookupCache == nil || s.originalAddress == "" {
		return
	}
	s.server.lookupCache.InvalidateUser(s.server.name, s.originalAddress)
	s.InfoLog("invalidated lookup cache entry", "reason", reason, "address", s.originalAddress, "backend", s.serverAddr)
}

// forwardRCPT sends the RCPT TO command to backend and handles response interception
func (s *Session) forwardRCPT(command string) {
	// Strip the RCPT TO parameters the backend does not take before forwarding
	// (DSN parameters among them: neither the proxy nor the backend announces DSN).
	cleanedCommand := stripUnsupportedRCPTParameters(command)
	if cleanedCommand != command {
		s.DebugLog("Stripped unsupported ESMTP parameters from RCPT TO", "original", command, "cleaned", cleanedCommand)
	}

	// IMPORTANT: If remotelookup resolved the recipient to a different email (ActualEmail),
	// we must rewrite the RCPT TO command to use the resolved email, not the original.
	// This handles cases where remotelookup returns a token-based or aliased address.
	// However, we must preserve the detail part (e.g., +test) from the original address.
	backendCommand := cleanedCommand
	if s.username != s.toAddress.BaseAddress() {
		// Username was resolved to a different email - rewrite RCPT TO
		// Extract any ESMTP parameters from cleaned command (after the address)
		params := ""
		if idx := strings.Index(cleanedCommand, ">"); idx != -1 && idx+1 < len(cleanedCommand) {
			params = strings.TrimSpace(cleanedCommand[idx+1:])
		}

		// Reconstruct resolved email with detail if present
		var resolvedRecipient string
		if s.toAddress.Detail() != "" {
			// Preserve detail part from original address
			resolvedAddr, parseErr := server.NewAddress(s.username)
			if parseErr == nil {
				resolvedRecipient = fmt.Sprintf("%s+%s@%s", resolvedAddr.LocalPart(), s.toAddress.Detail(), resolvedAddr.Domain())
			} else {
				// Fallback: use resolved username as-is if parsing fails
				s.WarnLog("Failed to parse resolved username for detail preservation", "username", s.username, "error", parseErr)
				resolvedRecipient = s.username
			}
		} else {
			resolvedRecipient = s.username
		}

		// Reconstruct RCPT TO with resolved email (with detail if present)
		if params != "" {
			backendCommand = fmt.Sprintf("RCPT TO:<%s> %s", resolvedRecipient, params)
		} else {
			backendCommand = fmt.Sprintf("RCPT TO:<%s>", resolvedRecipient)
		}
		s.DebugLog("Rewrote RCPT TO for backend", "original_recipient", s.to, "resolved_recipient", resolvedRecipient, "backend_command", backendCommand)
	}

	// Send the RCPT TO command
	s.DebugLog("Sending RCPT TO to backend", "command", backendCommand)
	_, err := s.backendWriter.WriteString(backendCommand + "\r\n")
	if err != nil {
		s.DebugLog("Failed to send RCPT TO", "error", err)
		s.sendResponse("451 4.4.2 Backend error")
		s.loseBackend() // poisons the transaction if a recipient was already accepted
		return
	}
	s.backendWriter.Flush()

	// Read the backend's response to RCPT TO (bounded, with read deadline)
	response, err := s.readBackendLine()
	if err != nil {
		s.DebugLog("Failed to read RCPT TO response", "error", err)
		s.sendResponse("451 4.4.2 Backend error")
		s.loseBackend()
		return
	}
	s.DebugLog("Backend RCPT TO response", "response", strings.TrimSpace(response))

	// Check if backend rejected the recipient BEFORE forwarding to client
	trimmedResponse := strings.TrimSpace(response)
	if strings.HasPrefix(trimmedResponse, "5") {
		// Backend rejected with permanent error (5xx)
		// This should NOT happen if remotelookup/cache said the user exists on this backend
		// This indicates a data consistency problem between remotelookup and backend, not a legitimate user-not-found
		// Return 4xx (temporary failure) instead of forwarding 5xx so sender can retry
		// This gives operators time to fix the data inconsistency without causing message loss
		s.WarnLog("backend rejected recipient - data inconsistency detected, returning temporary failure",
			"backend", s.serverAddr,
			"method", s.routingMethod,
			"from", s.sender,
			"to", s.to,
			"backend_response", trimmedResponse,
			"returned_to_client", "451 4.3.0",
			"issue", "remotelookup returned this backend but backend rejected user - check data consistency")

		// Invalidate cache entry to force fresh lookup on next attempt.
		// This prevents repeated routing to the wrong backend. InvalidateUser
		// derives the key exactly like Get/Set did (submitted address), so the
		// key formats can never drift apart.
		s.invalidateLookupCache("backend rejected recipient")

		// Override the backend's 5xx response with our own 4xx to allow retry
		s.sendResponse("451 4.3.0 Backend configuration issue, please try again later")
		return
	} else if strings.HasPrefix(trimmedResponse, "4") {
		// Backend rejected with temporary error (4xx) - forward as-is
		s.InfoLog("backend temporarily rejected recipient", "backend", s.serverAddr, "method", s.routingMethod, "from", s.sender, "to", s.to, "response", trimmedResponse)
		_, _ = s.writeClientReply(response, false)
		return
	}

	// Backend accepted (2xx). From here on this transaction is the backend's: a
	// lost backend can no longer be replaced.
	s.acceptedRcpts++

	// The session now delivers to this recipient's account, on a new backend
	// connection or on the one it already held: count it for that account
	// (once per session, however many of its recipients follow). This comes
	// before the reply, so the account's kick reaches the session from the
	// moment the MTA learns of the acceptance.
	if err := s.registerConnection(); err != nil {
		s.InfoLog("rejected connection registration", "error", err)
	}

	// Forward the backend's acceptance to the client.
	if _, err := s.writeClientReply(response, false); err != nil {
		return
	}

	// Log routing decision at INFO level with sender, recipient, and routing method
	s.InfoLog("routing to backend", "backend", s.serverAddr, "method", s.routingMethod, "from", s.sender, "to", s.to)
}

// close closes all connections.
func (s *Session) close() {
	s.mu.Lock()

	// Release connection limiter slot IMMEDIATELY (don't wait for goroutine to exit)
	if s.releaseConn != nil {
		s.releaseConn()
		s.releaseConn = nil // Prevent double-release
	}

	if kicked := s.kickedAccountID.Load(); kicked != 0 {
		s.InfoLog("connection kicked", "kicked_account_id", kicked)
	}

	// Log disconnection at INFO level
	duration := time.Since(s.startTime).Round(time.Second)
	s.InfoLog("disconnected", "from", s.sender, "to", s.to, "duration", duration, "backend", s.serverAddr)

	// Unregister connection SYNCHRONOUSLY to prevent leak
	// CRITICAL: Must be synchronous to ensure unregister completes before session goroutine exits
	// Background goroutine was causing leaks when server shutdown or high load prevented execution
	if s.server.connTracker != nil {
		// Use a new background context for this final operation, as s.ctx is likely already cancelled.
		// UnregisterConnection is fast (in-memory only), so this won't block for long
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		// Unregister all account IDs that we actually registered during this LMTP session.
		// LMTP sessions can contain multiple RCPTs; s.accountID is overwritten per RCPT.
		// If we were to unregister only s.accountID (the *last* RCPT), we would leak the
		// original registered user forever.
		// IMPORTANT: only unregister what we actually registered. There is
		// deliberately NO fallback to s.accountID here: handleRecipient sets
		// s.accountID even when registerConnection was never called (e.g. the
		// backend connect failed) or was rejected by a limit. Unregistering an
		// account that was never registered decrements connection counts owned
		// by the user's OTHER live sessions, eroding per-user limits.
		for id, registration := range s.registeredAccountIDs {
			s.server.connTracker.UnregisterSession(id, registration.kick)
			if !registration.counted {
				continue
			}
			// Use cached client address to avoid race with connection close
			if err := s.server.connTracker.UnregisterConnection(ctx, id, "LMTP", s.clientAddr); err != nil {
				// Connection tracking is non-critical monitoring data, so log but continue
				s.WarnLog("Failed to unregister connection", "error", err, "registered_account_id", id)
			}
		}
	}

	client, backend := s.clientConn, s.backendConn
	s.mu.Unlock()
	// Normal completion retains TLS close_notify. Forced shutdown/cancellation
	// closes the raw transports separately and can interrupt these closes.
	if client != nil {
		client.Close()
	}
	if backend != nil {
		backend.Close()
	}
}

// closeSessionTransport interrupts pending I/O before wrapper cleanup. In
// particular it never waits for TLS close_notify while holding a session lock.
func closeSessionTransport(conn net.Conn) {
	if conn != nil {
		if raw := server.RawConn(conn); raw != nil {
			raw.Close()
		}
		conn.Close()
	}
}

// registerConnection registers the connection in the database.
func (s *Session) registerConnection() error {
	// registerConnection is an in-memory tracking operation, but we still bound it with a timeout.
	// In production we use the configured DB query timeout as a convenient knob.
	// In unit tests (or misconfiguration), s.server.rdb can be nil, so fall back safely.
	queryTimeout := 1 * time.Second
	if s.server != nil && s.server.rdb != nil {
		queryTimeout = s.server.rdb.GetQueryTimeout()
	}
	ctx, cancel := context.WithTimeout(s.ctx, queryTimeout)
	defer cancel()

	// Use cached client address (real IP) to match UnregisterConnection in close()
	if s.server.connTracker != nil {
		// One LMTP session counts once per account, however many of its recipients
		// the backend accepts and however many backend connections it opens (after a
		// lost backend the next RCPT TO reconnects and lands here again), and close()
		// unregisters each account once.
		registration, subscribed := s.registeredAccountIDs[s.accountID]
		if !subscribed {
			if s.registeredAccountIDs == nil {
				s.registeredAccountIDs = make(map[int64]accountRegistration)
			}
			registration.kick = s.server.connTracker.RegisterSession(s.accountID)
			s.registeredAccountIDs[s.accountID] = registration
			go s.watchKick(s.accountID, registration.kick)
		}
		if registration.counted {
			return nil
		}
		err := s.server.connTracker.RegisterConnection(ctx, s.accountID, s.username, "LMTP", s.clientAddr)
		if err != nil {
			return err
		}
		registration.counted = true
		s.registeredAccountIDs[s.accountID] = registration
		return nil
	}
	return nil
}

// kickNoticeTimeout bounds the write of the 421 a kick sends before it closes
// the session, as the shutdown notice is bounded, for a client that stops reading.
const kickNoticeTimeout = time.Second

// watchKick ends the session when the tracker kicks accountID (it closes kick),
// whichever of the session's recipients the account is, and returns with the
// session otherwise. The kick is an intentional close, which RFC 5321 section
// 3.8 (LMTP is SMTP there, RFC 2033 section 4) allows only after a 421, sent
// "asynchronously from command receipt" if need be: watchKick writes it the way
// the shutdown notice does, then cancels the session context, which closes the
// client and backend transports (handleConnection). The MTA retries whatever it
// had not been told was delivered. It does not log: the session logger reads
// fields the command loop writes, so close() reports the kick.
func (s *Session) watchKick(accountID int64, kick <-chan struct{}) {
	select {
	case <-kick:
	case <-s.ctx.Done():
		return
	}
	if !s.kickedAccountID.CompareAndSwap(0, accountID) {
		return // another of the session's accounts was kicked: that watcher ends it
	}

	// Bound the wait for noticeMu (if the session goroutine is wedged flushing
	// an earlier reply to an unresponsive client) and for TLS close_notify.
	var aborted atomic.Bool
	abortTimer := time.AfterFunc(kickNoticeTimeout, func() {
		aborted.Store(true)
		s.cancel()
		s.mu.Lock()
		client, backend := s.clientConn, s.backendConn
		s.mu.Unlock()
		closeSessionTransport(client)
		closeSessionTransport(backend)
	})
	defer abortTimer.Stop()

	// noticeMu serializes the 421 with every session reply, greeting, STARTTLS,
	// and server shutdown notice: once closingNoticeSent is set, nothing else is
	// ever written after this 421.
	s.noticeMu.Lock()
	s.mu.Lock()
	conn := s.clientConn
	ready := s.greeted && !s.startTLSInProgress && !s.closingNoticeSent && !aborted.Load()
	s.closingNoticeSent = true
	s.mu.Unlock()
	if conn != nil && ready {
		if err := conn.SetWriteDeadline(time.Now().Add(kickNoticeTimeout)); err == nil {
			if _, err := fmt.Fprint(conn, "421 4.3.2 Service closing connection\r\n"); err == nil {
				conn.Close()
			}
		}
	}
	s.noticeMu.Unlock()

	s.cancel()
}

func isClosingError(err error) bool {
	return server.IsConnectionError(err)
}

// findParameter searches for a parameter with a given prefix in a list of arguments.
// It is case-insensitive and supports prefixes like "FROM:" or "TO:".
// It handles both "KEY:value" and "KEY: value" formats.
func findParameter(args []string, prefix string) (string, bool) {
	for i, arg := range args {
		// Handle "KEY: value" format where KEY: is a standalone token.
		if strings.ToUpper(arg) == prefix {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false // Found prefix but no value.
		}

		// Handle "KEY:value" format where it's a single token.
		if strings.HasPrefix(strings.ToUpper(arg), prefix) {
			return arg[len(prefix):], true
		}
	}
	return "", false
}

// hasSMTPUTF8Param reports whether the MAIL FROM arguments carry the SMTPUTF8 parameter
// (RFC 6531 §3.4; it takes no value).
func hasSMTPUTF8Param(args []string) bool {
	for _, arg := range args {
		if strings.EqualFold(arg, "SMTPUTF8") {
			return true
		}
	}
	return false
}

// mailSizeParameter reads the SIZE parameter of MAIL (RFC 1870 section 6) and checks it
// against limit, the size advertised in LHLO. It returns the declared size as given
// ("" for none) and the reply refusing the command ("" for none): 501 for a value that
// is not "size-value ::= 1*20DIGIT" (section 3 (4)) and for a second SIZE ("Only one
// SIZE parameter may be specified in a single MAIL command", section 6), 552 for a size
// above the limit (section 6.1 (2)). Without a limit no SIZE is advertised, and the
// parameter is ignored.
func mailSizeParameter(args []string, limit int64) (size, reply string) {
	if limit <= 0 {
		return "", ""
	}
	for _, arg := range args {
		key, value, _ := strings.Cut(arg, "=")
		if !strings.EqualFold(key, "SIZE") {
			continue
		}
		if size != "" || len(value) == 0 || len(value) > 20 || strings.Trim(value, "0123456789") != "" {
			return "", "501 5.5.4 Syntax error in SIZE parameter"
		}
		size = value
	}
	if size == "" {
		return "", ""
	}
	// Twenty digits can exceed an int64: the only error left is the range.
	if n, err := strconv.ParseInt(size, 10, 64); err != nil || n > limit {
		return "", "552 5.3.4 Message size exceeds fixed maximum message size"
	}
	return size, ""
}

// errBackendRefusedSize is the backend's 552 to the MAIL sent when connecting: its fixed
// maximum is below the declared size (RFC 1870 section 6.1 (2)).
var errBackendRefusedSize = errors.New("backend refused the declared message size")

// isSMTPUTF8Capability reports whether an LHLO reply line ("250-SMTPUTF8" or
// "250 SMTPUTF8") advertises the extension.
func isSMTPUTF8Capability(line string) bool {
	return len(line) > 4 && strings.EqualFold(strings.TrimSpace(line[4:]), "SMTPUTF8")
}

// isSIZECapability reports whether an LHLO reply line advertises SIZE (RFC 1870
// section 3), with or without a fixed maximum ("250-SIZE 52428800", "250 SIZE").
func isSIZECapability(line string) bool {
	if len(line) <= 4 {
		return false
	}
	keyword, _, _ := strings.Cut(strings.TrimSpace(line[4:]), " ")
	return strings.EqualFold(keyword, "SIZE")
}

// backendMailFrom is the MAIL command sent to the backend for the current transaction.
// The MTA's other MAIL parameters (RET and ENVID among them) are not forwarded.
// The SMTPUTF8 parameter goes with it only when the backend advertised the extension
// (RFC 6531 §3.2): a backend without it gets the plain command and, if the envelope is
// in fact non-ASCII, decides for itself — sora backends accept it — which is what keeps
// a mixed-version deployment delivering while the backends are upgraded.
// The declared SIZE goes with it only to a backend that advertised SIZE (RFC 1870
// section 4: "When supported by the server, a client may use the extended MAIL
// command"), so a backend whose fixed maximum is below the proxy's refuses the message
// before the body is sent, not after it (section 6.3).
func (s *Session) backendMailFrom() string {
	cmd := "MAIL FROM:<" + s.sender + ">"
	if s.declaredSize != "" && s.backendSIZE {
		cmd += " SIZE=" + s.declaredSize
	}
	if s.smtputf8 && s.backendSMTPUTF8 {
		cmd += " SMTPUTF8"
	}
	return cmd
}

// --- Transaction state (the backend's view of a transaction must stay the MTA's view) ---

// resetTransaction forgets the current mail transaction: on MAIL (a new one), RSET, and
// after the end-of-data replies were relayed.
func (s *Session) resetTransaction() {
	s.sender = ""
	s.to = ""
	s.mailFromReceived = false
	s.acceptedRcpts = 0
	s.txPoisoned = false
	s.backendHasMail = false
	s.smtputf8 = false
	s.declaredSize = ""
}

// loseBackend drops the backend connection. If the backend had already accepted a
// recipient of the current transaction, the transaction is poisoned: the MTA believes
// those recipients are accepted, so every further RCPT and DATA must answer 451 (retry
// the whole message) — never 503, which makes the MTA bounce the accepted recipients,
// and never a silent reconnect, after which a fresh backend would only know the later
// recipients and its single end-of-data reply would be attributed to the wrong one.
func (s *Session) loseBackend() {
	s.mu.Lock()
	if s.backendConn != nil {
		s.backendConn.Close()
		s.backendConn = nil
	}
	s.backendRoute = nil
	s.mu.Unlock()
	s.backendHasMail = false
	if s.acceptedRcpts > 0 {
		s.txPoisoned = true
	}
}

// forwardSimpleCommand sends one command line to the backend and returns its (single
// or multi-line) reply verbatim, CRLF included. ok is false when the backend connection
// failed, in which case it has been dropped (loseBackend) and nothing was relayed.
func (s *Session) forwardSimpleCommand(command string) (reply string, ok bool) {
	if s.backendConn == nil {
		return "", false
	}
	if _, err := s.backendWriter.WriteString(command + "\r\n"); err != nil {
		s.DebugLog("failed to send command to backend", "command", command, "error", err)
		s.loseBackend()
		return "", false
	}
	if err := s.backendWriter.Flush(); err != nil {
		s.DebugLog("failed to flush command to backend", "command", command, "error", err)
		s.loseBackend()
		return "", false
	}
	var b strings.Builder
	for lines := 0; lines < maxLHLOResponseLines; lines++ {
		line, err := s.readBackendLine()
		if err != nil {
			s.DebugLog("failed to read backend reply", "command", command, "error", err)
			s.loseBackend()
			return "", false
		}
		b.WriteString(line)
		if len(line) < 4 || line[3] != '-' {
			return b.String(), true
		}
	}
	s.DebugLog("backend reply exceeded the line limit", "command", command)
	s.loseBackend()
	return "", false
}

// userNotFoundError is the error for a recipient known not to exist, whether the
// knowledge is fresh or cached, so that a negative-cache hit gets the reply the fresh
// lookup gave. fromRemoteLookup says who reported the recipient unknown:
//   - the remote lookup, the authority on its users (a 404/3xx without database
//     fallback, or a 401/403 refusal of the account): 550, or 450 when
//     user_not_found_response = "tempfail". Backend health does not enter into it.
//   - the proxy's own database, which may lag the backends: 550 only while a backend
//     of the default pool is healthy, else 450 (a proxy that cannot verify anything
//     must not bounce). user_not_found_response does not apply to the database
//     fallback.
func (s *Session) userNotFoundError(fromRemoteLookup bool) error {
	if fromRemoteLookup {
		if s.server.remotelookupConfig != nil && s.server.remotelookupConfig.GetUserNotFoundResponse() == "tempfail" {
			return server.ErrUserNotFoundTempFail
		}
		return server.ErrUserNotFound
	}
	if !s.server.connManager.HasHealthyPoolBackends() {
		return server.ErrUserNotFoundTempFail
	}
	return server.ErrUserNotFound
}

// Deadlines for the inline message relay.
const (
	// relayBackendWriteDeadline bounds each write of body data to the backend, so a
	// backend that stops draining its socket cannot hold the session goroutine and its
	// connection slot until the absolute session timeout.
	relayBackendWriteDeadline = 30 * time.Second
	// relayEndOfDataTimeout bounds the wait for the backend's end-of-data replies. It
	// must outlive the backend's own DATA processing cap (60 s) by a wide margin: a
	// proxy that gives up first leaves the backend free to commit a message the MTA is
	// told nothing about, which the MTA then re-sends.
	relayEndOfDataTimeout = 5 * time.Minute
)

// relayMessageData relays one DATA body from the client to the backend, then the
// backend's end-of-data replies — one final reply line per accepted recipient (RFC 2033
// §4.2) — back to the client, and reports whether the session may continue with the
// next command. It runs inline in the session goroutine and stops exactly at the
// end-of-data marker, so anything the client pipelined after it (the next MAIL FROM)
// stays in clientReader for the command loop: the connection is never a raw pipe, and
// every later transaction on it is routed like the first.
//
// false means the session must end. The proxy never synthesizes an end-of-data reply:
// when the backend closes or times out first, whatever it sent is relayed and the client
// connection is dropped, so the MTA defers and retries (the backend deduplicates a
// message it did commit).
func (s *Session) relayMessageData() bool {
	var bytesIn, bytesOut int64
	defer func() {
		metrics.BytesThroughput.WithLabelValues("lmtp_proxy", "in").Add(float64(bytesIn))
		metrics.BytesThroughput.WithLabelValues("lmtp_proxy", "out").Add(float64(bytesOut))
	}()

	// The end-of-data marker is what the backend's DATA reader (go-smtp) recognizes as
	// one: a line that is exactly ".\r\n", read at the start of a line whose predecessor
	// ended in "\r\n". A chunk of an over-long line is never at the start of a line, and
	// a bare-LF predecessor leaves the backend inside the body — mirror both, or the
	// proxy and the backend would disagree about where the message ends.
	atLineStart, prevCRLF := true, true
	crlf := []byte("\r\n")
	for {
		// Idle deadline only when the next read will hit the wire.
		if s.server.authIdleTimeout > 0 && s.clientReader.Buffered() == 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.authIdleTimeout)); err != nil {
				s.DebugLog("failed to set read deadline during DATA", "error", err)
				s.loseBackend()
				return false
			}
		}
		// ReadSlice (not ReadString) so an oversized line is forwarded in buffer-sized
		// chunks instead of being accumulated in memory in its entirety.
		line, err := s.clientReader.ReadSlice('\n')
		full := err == nil
		if len(line) > 0 {
			end := full && atLineStart && prevCRLF && len(line) == 3 && line[0] == '.' && line[1] == '\r' && line[2] == '\n'
			if derr := s.backendConn.SetWriteDeadline(time.Now().Add(relayBackendWriteDeadline)); derr != nil {
				s.DebugLog("failed to set backend write deadline", "error", derr)
				s.loseBackend()
				return false
			}
			n, werr := s.backendWriter.Write(line)
			bytesIn += int64(n)
			if werr == nil && (end || s.clientReader.Buffered() == 0) {
				// Flush once the client buffer is drained (or at the end): prompt, but not
				// one syscall per body line.
				werr = s.backendWriter.Flush()
			}
			if werr != nil {
				if !isClosingError(werr) {
					s.InfoLog("backend connection failed during DATA", "error", werr)
				}
				s.loseBackend()
				return false
			}
			if end {
				break
			}
			atLineStart = full
			prevCRLF = full && bytes.HasSuffix(line, crlf)
		}
		if err != nil {
			if err == bufio.ErrBufferFull {
				continue // long line: the chunk was forwarded; keep reading
			}
			// The client is gone (or idle) before the end of the message. Drop the
			// backend connection outright rather than half-closing it: its DATA reader
			// must see the connection fail, not a truncated body it could commit.
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.DebugLog("idle timeout during DATA")
			} else if !isClosingError(err) {
				s.DebugLog("error reading from client during DATA", "error", err)
			}
			s.loseBackend()
			return false
		}
	}
	if err := s.backendConn.SetWriteDeadline(time.Time{}); err != nil {
		s.DebugLog("failed to clear backend write deadline", "error", err)
	}

	// End-of-data replies: the backend sends one final reply line per recipient it
	// accepted (that is what acceptedRcpts counts). Buffer each recipient's complete
	// single- or multi-line reply and flush it atomically under noticeMu so an async
	// 421 notice never splits continuation lines or shifts positional LMTP replies.
	want := s.acceptedRcpts
	if err := s.backendConn.SetReadDeadline(time.Now().Add(relayEndOfDataTimeout)); err != nil {
		s.DebugLog("failed to set backend read deadline for end-of-data replies", "error", err)
		s.loseBackend()
		return false
	}
	defer func() {
		if s.backendConn != nil {
			_ = s.backendConn.SetReadDeadline(time.Time{})
		}
	}()
	for got := 0; got < want; got++ {
		var b strings.Builder
		complete := false
		for lines := 0; lines < maxLHLOResponseLines; lines++ {
			reply, err := server.ReadBoundedLine(s.backendReader, backendResponseLineMax)
			if err != nil {
				s.InfoLog("backend closed or timed out before all end-of-data replies were relayed",
					"expected", want, "relayed", got, "error", err)
				s.loseBackend()
				return false
			}
			b.WriteString(reply)
			if len(reply) >= 4 && reply[3] != '-' {
				complete = true
				break
			}
		}
		if !complete {
			s.InfoLog("backend end-of-data reply exceeded line limit",
				"expected", want, "relayed", got, "limit", maxLHLOResponseLines)
			s.loseBackend()
			return false
		}
		n, ferr := s.writeClientReply(b.String(), false)
		bytesOut += int64(n)
		if ferr != nil {
			if !errors.Is(ferr, errSessionClosing) {
				s.DebugLog("client gone while relaying end-of-data replies", "error", ferr)
			}
			s.loseBackend()
			return false
		}
	}
	return true
}

// backendInMaintenance reports whether the backend the session holds is in maintenance, by
// the name it was routed by or by the address it is connected to: a name that does not
// resolve for the check still leaves the address.
func (s *Session) backendInMaintenance() bool {
	if s.server.connManager.InMaintenance(s.serverAddr) {
		return true
	}
	remote := s.backendConn.RemoteAddr()
	return remote != nil && s.server.connManager.InMaintenance(remote.String())
}
