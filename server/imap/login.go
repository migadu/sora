package imap

import (
	"crypto/subtle"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
)

// Tilde is default separator for master password
const MasterUsernameSeparator = "~"

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
			s.Log("[LOGIN] rate limited: %v", err)
			// Track rate limiting as a specific error type
			metrics.ProtocolErrors.WithLabelValues("imap", "LOGIN", "rate_limited", "client_error").Inc()
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeAuthenticationFailed,
				Text: "Too many authentication attempts. Please try again later.",
			}
		}
	}

	authAddress, proxyUser := parseMasterLogin(address)

	// Master password login
	if len(s.server.masterUsername) > 0 && proxyUser != "" && checkMasterCredential(proxyUser, s.server.masterUsername) {
		address, err := server.NewAddress(authAddress)
		if err != nil {
			s.Log("[LOGIN] failed to parse address: %v", err)
			// Track invalid address format as client error
			metrics.ProtocolErrors.WithLabelValues("imap", "LOGIN", "invalid_address", "client_error").Inc()
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeAuthenticationFailed,
				Text: "Address not in the correct format",
			}
		}

		if checkMasterCredential(password, s.server.masterPassword) {
			userID, err := s.server.rdb.GetAccountIDByAddressWithRetry(s.ctx, address.FullAddress())
			if err != nil {
				return err
			}

			s.IMAPUser = NewIMAPUser(address, userID)
			s.Session.User = &s.IMAPUser.User

			authCount := s.server.authenticatedConnections.Add(1)
			totalCount := s.server.totalConnections.Load()
			s.Log("[LOGIN] user %s/%s authenticated with master password (connections: total=%d, authenticated=%d)",
				address, proxyUser, totalCount, authCount)

			// Prometheus metrics - successful authentication
			metrics.AuthenticationAttempts.WithLabelValues("imap", "success").Inc()
			metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap").Inc()

			// Record successful authentication
			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, address.FullAddress(), true)
			}

			// Register connection for tracking
			s.registerConnection(address.FullAddress())

			// Start termination poller to check for kick commands
			s.startTerminationPoller()

			return nil
		}

		// Record failed master password authentication
		metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
		if s.server.authLimiter != nil {
			s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, authAddress, false)
		}
	}

	addressSt, err := server.NewAddress(address)
	if err != nil {
		s.Log("[LOGIN] failed to parse address: %v", err)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Address not in the correct format",
		}
	}

	s.Log("[LOGIN] authentication attempt with address %s", addressSt.FullAddress())

	// Use base address (without +detail) for authentication
	userID, err := s.server.rdb.AuthenticateWithRetry(s.ctx, addressSt.BaseAddress(), password)
	if err != nil {
		s.Log("[LOGIN] authentication failed: %v", err)

		// Record failed authentication
		metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
		if s.server.authLimiter != nil {
			s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, addressSt.FullAddress(), false)
		}

		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Invalid address or password",
		}
	}

	// Ensure default mailboxes (INBOX/Drafts/Sent/Spam/Trash) exist
	err = s.server.rdb.CreateDefaultMailboxesWithRetry(s.ctx, userID)
	if err != nil {
		return s.internalError("failed to create default mailboxes: %v", err)
	}

	s.IMAPUser = NewIMAPUser(addressSt, userID)
	s.Session.User = &s.IMAPUser.User

	authCount := s.server.authenticatedConnections.Add(1)
	totalCount := s.server.totalConnections.Load()
	s.Log("[LOGIN] user %s authenticated (connections: total=%d, authenticated=%d)",
		address, totalCount, authCount)

	// Prometheus metrics - successful authentication
	metrics.AuthenticationAttempts.WithLabelValues("imap", "success").Inc()
	metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap").Inc()

	// Domain and user tracking
	metrics.TrackDomainConnection("imap", addressSt.Domain())
	metrics.TrackUserActivity("imap", addressSt.FullAddress(), "connection", 1)

	// Record successful authentication
	if s.server.authLimiter != nil {
		s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, addressSt.FullAddress(), true)
	}

	// Register connection for tracking
	s.registerConnection(addressSt.FullAddress())

	// Start termination poller to check for kick commands
	s.startTerminationPoller()

	// Trigger cache warmup for the authenticated user
	s.triggerCacheWarmup()

	return nil
}

func parseMasterLogin(username string) (realuser, authuser string) {
	parts := strings.SplitN(username, MasterUsernameSeparator, 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return username, ""
}

func checkMasterCredential(provided string, actual []byte) bool {
	return subtle.ConstantTimeCompare([]byte(provided), actual) == 1
}
