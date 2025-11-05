package imap

import (
	"crypto/subtle"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
)

func (s *IMAPSession) Login(address, password string) error {
	// Get the underlying net.Conn for proxy-aware rate limiting
	netConn := s.conn.NetConn()

	// Create proxy info from session data
	var proxyInfo *server.ProxyProtocolInfo
	if s.ProxyIP != "" {
		// This is a proxied connection, reconstruct proxy info
		proxyInfo = &server.ProxyProtocolInfo{
			SrcIP: s.RemoteIP,
			// Note: ProxyIP is not a field in ProxyProtocolInfo,
			// but GetConnectionIPs will extract the proxy from the connection
		}
	}

	// Apply progressive authentication delay BEFORE any other checks
	// Create a fake net.Addr from the RemoteIP for delay calculation
	remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
	server.ApplyAuthenticationDelay(s.ctx, s.server.authLimiter, remoteAddr, "IMAP-LOGIN")

	// Check authentication rate limiting after delay using proxy-aware method
	if s.server.authLimiter != nil {
		if err := s.server.authLimiter.CanAttemptAuthWithProxy(s.ctx, netConn, proxyInfo, address); err != nil {
			s.DebugLog("[LOGIN] rate limited: %v", err)
			// Track rate limiting as a specific error type
			metrics.ProtocolErrors.WithLabelValues("imap", "LOGIN", "rate_limited", "client_error").Inc()
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeAuthenticationFailed,
				Text: "Too many authentication attempts. Please try again later.",
			}
		}
	}

	// Parse address with potential suffix (master username or prelookup token)
	addressParsed, err := server.NewAddress(address)
	if err != nil {
		s.DebugLog("[LOGIN] failed to parse address: %v", err)
		// Track invalid address format as client error
		metrics.ProtocolErrors.WithLabelValues("imap", "LOGIN", "invalid_address", "client_error").Inc()
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Address not in the correct format",
		}
	}

	// Master username authentication: user@domain.com@MASTER_USERNAME
	// Check if suffix matches configured MasterUsername
	if len(s.server.masterUsername) > 0 && addressParsed.HasSuffix() && checkMasterCredential(addressParsed.Suffix(), s.server.masterUsername) {
		// Suffix matches MasterUsername, authenticate with MasterPassword
		if checkMasterCredential(password, s.server.masterPassword) {
			// Use base address (without suffix) to get account
			AccountID, err := s.server.rdb.GetAccountIDByAddressWithRetry(s.ctx, addressParsed.BaseAddress())
			if err != nil {
				return err
			}

			s.IMAPUser = NewIMAPUser(addressParsed, AccountID)
			s.Session.User = &s.IMAPUser.User

			authCount := s.server.authenticatedConnections.Add(1)
			totalCount := s.server.totalConnections.Load()
			s.InfoLog("[LOGIN] user %s authenticated with master username %s (connections: total=%d, authenticated=%d)",
				addressParsed.BaseAddress(), addressParsed.Suffix(), totalCount, authCount)

			// Prometheus metrics - successful authentication
			metrics.AuthenticationAttempts.WithLabelValues("imap", "success").Inc()
			metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap").Inc()

			// Record successful authentication
			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, addressParsed.BaseAddress(), true)
			}

			// Register connection for tracking
			if err := s.registerConnection(addressParsed.BaseAddress()); err != nil {
				// Connection limit reached - undo authentication and reject
				metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap").Dec()
				s.IMAPUser = nil
				s.Session.User = nil
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeLimit,
					Text: "Maximum connections reached",
				}
			}

			// Start termination poller to check for kick commands
			s.startTerminationPoller()

			return nil
		}

		// Record failed master password authentication
		metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
		if s.server.authLimiter != nil {
			s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, addressParsed.BaseAddress(), false)
		}

		// Master username suffix was provided but master password was wrong - fail immediately
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Invalid master credentials",
		}
	}

	// Regular authentication - use the already parsed address
	// If it has a suffix but didn't match MasterUsername, fall through to regular auth
	// (this allows the suffix to be used for prelookup in proxy scenarios)

	s.DebugLog("[LOGIN] authentication attempt with address %s", addressParsed.BaseAddress())

	// Use base address (without +detail and without suffix) for authentication
	AccountID, err := s.server.rdb.AuthenticateWithRetry(s.ctx, addressParsed.BaseAddress(), password)
	if err != nil {
		s.DebugLog("[LOGIN] authentication failed: %v", err)

		// Record failed authentication
		metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
		if s.server.authLimiter != nil {
			s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, addressParsed.BaseAddress(), false)
		}

		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Invalid address or password",
		}
	}

	// Ensure default mailboxes (INBOX/Drafts/Sent/Spam/Trash) exist
	err = s.server.rdb.CreateDefaultMailboxesWithRetry(s.ctx, AccountID)
	if err != nil {
		return s.internalError("failed to create default mailboxes: %v", err)
	}

	s.IMAPUser = NewIMAPUser(addressParsed, AccountID)
	s.Session.User = &s.IMAPUser.User

	authCount := s.server.authenticatedConnections.Add(1)
	totalCount := s.server.totalConnections.Load()
	s.InfoLog("[LOGIN] user %s authenticated (connections: total=%d, authenticated=%d)",
		addressParsed.BaseAddress(), totalCount, authCount)

	// Prometheus metrics - successful authentication
	metrics.AuthenticationAttempts.WithLabelValues("imap", "success").Inc()
	metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap").Inc()

	// Domain and user tracking
	metrics.TrackDomainConnection("imap", addressParsed.Domain())
	metrics.TrackUserActivity("imap", addressParsed.BaseAddress(), "connection", 1)

	// Record successful authentication
	if s.server.authLimiter != nil {
		s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, addressParsed.BaseAddress(), true)
	}

	// Register connection for tracking
	if err := s.registerConnection(addressParsed.BaseAddress()); err != nil {
		// Connection limit reached - undo authentication and reject
		metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap").Dec()
		s.IMAPUser = nil
		s.Session.User = nil
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeLimit,
			Text: "Maximum connections reached",
		}
	}

	// Start termination poller to check for kick commands
	s.startTerminationPoller()

	// Trigger cache warmup for the authenticated user
	s.triggerCacheWarmup()

	return nil
}

func checkMasterCredential(provided string, actual []byte) bool {
	return subtle.ConstantTimeCompare([]byte(provided), actual) == 1
}
