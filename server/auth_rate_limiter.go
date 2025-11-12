package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/migadu/sora/config"
)

// ErrRateLimitExceeded is returned when rate limit is exceeded
// This sentinel error allows protocol handlers to provide appropriate responses (e.g., IMAP BYE with ALERT)
var ErrRateLimitExceeded = errors.New("rate limit exceeded")

// RateLimitError contains details about why rate limiting was triggered
type RateLimitError struct {
	Reason       string // "ip_blocked" or "ip_username_blocked"
	IP           string
	Username     string
	FailureCount int
	BlockedUntil time.Time
	BaseError    error
}

func (e *RateLimitError) Error() string {
	if e.BaseError != nil {
		return e.BaseError.Error()
	}
	if e.Reason == "ip_username_blocked" {
		return fmt.Sprintf("authentication temporarily blocked for user %s from IP %s until %v (%d failed attempts)",
			e.Username, e.IP, e.BlockedUntil.Format("15:04:05"), e.FailureCount)
	}
	return fmt.Sprintf("IP %s is temporarily blocked until %v (failed %d times)",
		e.IP, e.BlockedUntil.Format("15:04:05"), e.FailureCount)
}

func (e *RateLimitError) Unwrap() error {
	return ErrRateLimitExceeded
}

// StringAddr implements net.Addr interface for string addresses
type StringAddr struct {
	Addr string
}

func (s *StringAddr) String() string {
	return s.Addr
}

func (s *StringAddr) Network() string {
	return "tcp"
}

// AuthRateLimiterConfig is an alias for config.AuthRateLimiterConfig for compatibility
type AuthRateLimiterConfig = config.AuthRateLimiterConfig

// DefaultAuthRateLimiterConfig returns sensible defaults for authentication rate limiting
func DefaultAuthRateLimiterConfig() AuthRateLimiterConfig {
	return config.DefaultAuthRateLimiterConfig()
}

// AuthLimiter interface that both AuthRateLimiter and EnhancedAuthRateLimiter implement
type AuthLimiter interface {
	CanAttemptAuth(ctx context.Context, remoteAddr net.Addr, username string) error
	RecordAuthAttempt(ctx context.Context, remoteAddr net.Addr, username string, success bool)
	// New methods with proxy awareness
	CanAttemptAuthWithProxy(ctx context.Context, conn net.Conn, proxyInfo *ProxyProtocolInfo, username string) error
	RecordAuthAttemptWithProxy(ctx context.Context, conn net.Conn, proxyInfo *ProxyProtocolInfo, username string, success bool)
	// TCP-level IP blocking checks (for connection rejection before TLS handshake)
	IsIPBlocked(remoteAddr net.Addr) bool
	IsIPBlockedWithProxy(conn net.Conn, proxyInfo *ProxyProtocolInfo) bool
	GetStats(ctx context.Context, windowDuration time.Duration) map[string]any
	Stop()
}

// AuthRateLimiter provides two-tier rate limiting: IP+username and IP-only blocking
type AuthRateLimiter struct {
	config   AuthRateLimiterConfig
	protocol string

	// Trusted networks for exemption
	trustedNetworks []string

	// Tier 1: IP+username blocking (fast, protects shared IPs)
	blockedIPUsernames map[string]*BlockedIPUsernameInfo
	ipUsernameMu       sync.RWMutex

	// Tier 2: IP-only blocking (slow, catches distributed attacks)
	blockedIPs      map[string]*BlockedIPInfo
	ipFailureCounts map[string]*IPFailureInfo
	ipMu            sync.RWMutex

	// Username failure tracking (statistics only, cluster-synchronized)
	usernameFailureCounts map[string]*UsernameFailureInfo
	usernameMu            sync.RWMutex

	// Cluster integration (optional)
	clusterLimiter *ClusterRateLimiter

	stopCleanup chan struct{}
}

// BlockedIPUsernameInfo tracks specific IP+username combinations that are temporarily blocked
type BlockedIPUsernameInfo struct {
	BlockedUntil time.Time
	FailureCount int
	FirstFailure time.Time
	LastFailure  time.Time
	Protocol     string
	IP           string
	Username     string
}

// BlockedIPInfo tracks IPs that are temporarily blocked
type BlockedIPInfo struct {
	BlockedUntil time.Time
	FailureCount int
	FirstFailure time.Time
	LastFailure  time.Time
	Protocol     string
}

// IPFailureInfo tracks failure counts and delays for progressive delays
type IPFailureInfo struct {
	FailureCount int
	FirstFailure time.Time
	LastFailure  time.Time
	LastDelay    time.Duration
}

// UsernameFailureInfo tracks failure counts per username (cluster-synchronized)
type UsernameFailureInfo struct {
	FailureCount int
	FirstFailure time.Time
	LastFailure  time.Time
}

// NewAuthRateLimiter creates a new authentication rate limiter.
func NewAuthRateLimiter(protocol string, config AuthRateLimiterConfig) *AuthRateLimiter {
	return NewAuthRateLimiterWithTrustedNetworks(protocol, config, nil)
}

// NewAuthRateLimiterWithTrustedNetworks creates a new authentication rate limiter with trusted networks exemption.
func NewAuthRateLimiterWithTrustedNetworks(protocol string, config AuthRateLimiterConfig, trustedNetworks []string) *AuthRateLimiter {
	if !config.Enabled {
		return nil
	}

	limiter := &AuthRateLimiter{
		config:                config,
		protocol:              protocol,
		trustedNetworks:       trustedNetworks,
		blockedIPUsernames:    make(map[string]*BlockedIPUsernameInfo),
		blockedIPs:            make(map[string]*BlockedIPInfo),
		ipFailureCounts:       make(map[string]*IPFailureInfo),
		usernameFailureCounts: make(map[string]*UsernameFailureInfo),
		stopCleanup:           make(chan struct{}),
	}

	// Start background cleanup routine
	go limiter.cleanupRoutine(config.CacheCleanupInterval)

	logger.Debug("Auth limiter: Initialized", "protocol", protocol,
		"max_attempts_per_ip_username", config.MaxAttemptsPerIPUsername, "ip_username_block_duration", config.IPUsernameBlockDuration,
		"max_attempts_per_ip", config.MaxAttemptsPerIP, "ip_block_duration", config.IPBlockDuration)

	return limiter
}

// SetClusterLimiter sets the cluster rate limiter for cluster-wide synchronization
func (a *AuthRateLimiter) SetClusterLimiter(clusterLimiter *ClusterRateLimiter) {
	if a == nil {
		return
	}
	a.clusterLimiter = clusterLimiter
}

// CanAttemptAuth checks if authentication can be attempted using two-tier blocking
func (a *AuthRateLimiter) CanAttemptAuth(ctx context.Context, remoteAddr net.Addr, username string) error {
	if a == nil {
		return nil
	}

	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	// TIER 1: Check if IP+username combination is blocked (fast, strict)
	// This protects shared IPs (corporate gateways) by blocking specific users
	if username != "" && a.config.MaxAttemptsPerIPUsername > 0 {
		ipUsernameKey := ip + "|" + username
		a.ipUsernameMu.RLock()
		if blocked, exists := a.blockedIPUsernames[ipUsernameKey]; exists {
			if !blocked.BlockedUntil.IsZero() && time.Now().Before(blocked.BlockedUntil) {
				a.ipUsernameMu.RUnlock()
				logger.Info("Auth rate limiter: Rejecting authentication (IP+username blocked)",
					"protocol", a.protocol,
					"ip", ip,
					"username", username,
					"failure_count", blocked.FailureCount,
					"blocked_until", blocked.BlockedUntil.Format(time.RFC3339))
				return &RateLimitError{
					Reason:       "ip_username_blocked",
					IP:           ip,
					Username:     username,
					FailureCount: blocked.FailureCount,
					BlockedUntil: blocked.BlockedUntil,
					BaseError:    ErrRateLimitExceeded,
				}
			}
			// Check if block has expired (has BlockedUntil set and it's in the past)
			if !blocked.BlockedUntil.IsZero() && time.Now().After(blocked.BlockedUntil) {
				// Block has expired, remove it - must upgrade to write lock
				a.ipUsernameMu.RUnlock()
				a.ipUsernameMu.Lock()
				delete(a.blockedIPUsernames, ipUsernameKey)
				a.ipUsernameMu.Unlock()
			} else {
				// Not blocked or still tracking failures - keep the entry
				a.ipUsernameMu.RUnlock()
			}
		} else {
			a.ipUsernameMu.RUnlock()
		}
	}

	// TIER 2: Check if entire IP is blocked (slow, lenient)
	// This catches distributed attacks trying many users from same IP
	if a.config.MaxAttemptsPerIP > 0 {
		a.ipMu.RLock()
		if blocked, exists := a.blockedIPs[ip]; exists {
			if time.Now().Before(blocked.BlockedUntil) {
				a.ipMu.RUnlock()
				logger.Info("Auth rate limiter: Rejecting authentication (IP blocked)",
					"protocol", a.protocol,
					"ip", ip,
					"username", username,
					"failure_count", blocked.FailureCount,
					"blocked_until", blocked.BlockedUntil.Format(time.RFC3339))
				return &RateLimitError{
					Reason:       "ip_blocked",
					IP:           ip,
					Username:     username,
					FailureCount: blocked.FailureCount,
					BlockedUntil: blocked.BlockedUntil,
					BaseError:    ErrRateLimitExceeded,
				}
			}
			// Block has expired, remove it - must upgrade to write lock
			a.ipMu.RUnlock()
			a.ipMu.Lock()
			delete(a.blockedIPs, ip)
			a.ipMu.Unlock()
		} else {
			a.ipMu.RUnlock()
		}
	}

	// Username failure tracking is for statistics and monitoring only
	// DO NOT block based on username-only failures - this creates a DoS vector
	//
	// Username tracking is still useful for:
	// - Cluster-wide statistics
	// - Detecting compromised accounts (high failure rate from many IPs)
	// - Alerting/monitoring
	//
	// But we intentionally DO NOT block here because:
	// - An attacker could lock out any user by trying wrong passwords
	// - Legitimate users with correct passwords would be blocked
	// - The failure counter can never clear if auth is blocked before verification

	return nil
}

// IsIPBlocked checks if an IP is currently blocked (Tier 2 only - IP-level blocking).
// This is used for TCP-level connection rejection, before we know the username.
// Returns true if the IP should be rejected at the TCP accept level.
func (a *AuthRateLimiter) IsIPBlocked(remoteAddr net.Addr) bool {
	if a == nil || a.config.MaxAttemptsPerIP == 0 {
		return false // Rate limiting disabled or Tier 2 disabled
	}

	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	// Check if IP is in trusted networks (never block trusted IPs)
	if a.isFromTrustedNetwork(ip) {
		return false
	}

	// Check Tier 2: IP-only blocking
	a.ipMu.RLock()
	defer a.ipMu.RUnlock()

	if blocked, exists := a.blockedIPs[ip]; exists {
		if time.Now().Before(blocked.BlockedUntil) {
			return true // IP is currently blocked
		}
	}

	return false // IP is not blocked
}

// IsIPBlockedWithProxy checks if an IP is currently blocked, supporting PROXY protocol.
// This is used for TCP-level connection rejection with proper proxy IP detection.
func (a *AuthRateLimiter) IsIPBlockedWithProxy(conn net.Conn, proxyInfo *ProxyProtocolInfo) bool {
	if a == nil || a.config.MaxAttemptsPerIP == 0 {
		return false // Rate limiting disabled or Tier 2 disabled
	}

	// Determine real client IP (with PROXY protocol support)
	var realClientIP string
	if proxyInfo != nil && proxyInfo.SrcIP != "" {
		realClientIP = proxyInfo.SrcIP
	} else {
		ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			realClientIP = conn.RemoteAddr().String()
		} else {
			realClientIP = ip
		}
	}

	// Check if IP is in trusted networks (never block trusted IPs)
	if a.isFromTrustedNetwork(realClientIP) {
		return false
	}

	// Check Tier 2: IP-only blocking
	a.ipMu.RLock()
	defer a.ipMu.RUnlock()

	if blocked, exists := a.blockedIPs[realClientIP]; exists {
		if time.Now().Before(blocked.BlockedUntil) {
			return true // IP is currently blocked
		}
	}

	return false // IP is not blocked
}

// CanAttemptAuthWithProxy checks if authentication can be attempted with proper proxy IP detection
func (a *AuthRateLimiter) CanAttemptAuthWithProxy(ctx context.Context, conn net.Conn, proxyInfo *ProxyProtocolInfo, username string) error {
	if a == nil {
		return nil
	}

	// Extract real client IP and proxy IP
	clientIP, proxyIP := GetConnectionIPs(conn, proxyInfo)

	// Check if the real client IP is from a trusted network
	if a.isFromTrustedNetwork(clientIP) {
		if proxyIP != "" {
			logger.Debug("Auth limiter: Skipping rate limiting for trusted client", "protocol", a.protocol, "client", clientIP, "proxy", proxyIP)
		} else {
			logger.Debug("Auth limiter: Skipping rate limiting for trusted client", "protocol", a.protocol, "client", clientIP)
		}
		return nil
	}

	// Use the real client IP for rate limiting
	clientAddr := &StringAddr{Addr: clientIP}
	return a.CanAttemptAuth(ctx, clientAddr, username)
}

// RecordAuthAttemptWithProxy records an authentication attempt with proper proxy IP detection
func (a *AuthRateLimiter) RecordAuthAttemptWithProxy(ctx context.Context, conn net.Conn, proxyInfo *ProxyProtocolInfo, username string, success bool) {
	if a == nil {
		return
	}

	// Extract real client IP and proxy IP
	clientIP, proxyIP := GetConnectionIPs(conn, proxyInfo)

	// Check if the real client IP is from a trusted network
	if a.isFromTrustedNetwork(clientIP) {
		if proxyIP != "" {
			logger.Debug("Auth limiter: Skipping rate limiting recording for trusted client", "protocol", a.protocol, "client", clientIP, "proxy", proxyIP)
		} else {
			logger.Debug("Auth limiter: Skipping rate limiting recording for trusted client", "protocol", a.protocol, "client", clientIP)
		}
		return
	}

	// Use the real client IP for rate limiting
	clientAddr := &StringAddr{Addr: clientIP}
	a.RecordAuthAttempt(ctx, clientAddr, username, success)
}

// isFromTrustedNetwork checks if an IP address is in the trusted networks
func (a *AuthRateLimiter) isFromTrustedNetwork(ipStr string) bool {
	if len(a.trustedNetworks) == 0 {
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check against trusted networks
	for _, cidr := range a.trustedNetworks {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// RecordAuthAttempt records an authentication attempt with fast blocking and delays
func (a *AuthRateLimiter) RecordAuthAttempt(ctx context.Context, remoteAddr net.Addr, username string, success bool) {
	if a == nil {
		return
	}

	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	now := time.Now()

	if !success {
		// Failed authentication: track IP+username (Tier 1), IP-only (Tier 2), and username (statistics)
		a.updateIPUsernameFailure(ip, username, now) // Tier 1: Fast IP+username blocking
		a.updateFailureTracking(ip, now)             // Tier 2: Slow IP-only blocking
		a.updateUsernameFailure(username, now)       // Statistics only
	} else {
		// Successful authentication: clear all tracking
		a.clearIPUsernameFailure(ip, username) // Clear Tier 1
		a.clearFailureTracking(ip)             // Clear Tier 2
		a.clearUsernameFailure(username)       // Clear statistics
	}
}

// GetAuthenticationDelay returns delay duration for progressive delays
func (a *AuthRateLimiter) GetAuthenticationDelay(remoteAddr net.Addr) time.Duration {
	if a == nil {
		return 0
	}

	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	a.ipMu.RLock()
	defer a.ipMu.RUnlock()

	if info, exists := a.ipFailureCounts[ip]; exists && info.FailureCount >= a.config.DelayStartThreshold {
		return info.LastDelay
	}

	return 0
}

func (a *AuthRateLimiter) updateFailureTracking(ip string, failureTime time.Time) {
	if a.config.MaxAttemptsPerIP == 0 {
		return // Skip if IP-only blocking is disabled
	}

	a.ipMu.Lock()
	defer a.ipMu.Unlock()

	info, exists := a.ipFailureCounts[ip]
	if !exists {
		info = &IPFailureInfo{FirstFailure: failureTime, LastDelay: 0}
		a.ipFailureCounts[ip] = info
	}

	info.FailureCount++
	info.LastFailure = failureTime

	if info.FailureCount >= a.config.DelayStartThreshold {
		if info.LastDelay == 0 {
			info.LastDelay = a.config.InitialDelay
		} else {
			info.LastDelay = time.Duration(float64(info.LastDelay) * a.config.DelayMultiplier)
			if info.LastDelay > a.config.MaxDelay {
				info.LastDelay = a.config.MaxDelay
			}
		}
	}

	if info.FailureCount >= a.config.MaxAttemptsPerIP {
		blockedUntil := failureTime.Add(a.config.IPBlockDuration)
		// Already have ipMu lock from line 338, no need to lock again
		a.blockedIPs[ip] = &BlockedIPInfo{
			BlockedUntil: blockedUntil,
			FailureCount: info.FailureCount,
			FirstFailure: info.FirstFailure,
			LastFailure:  failureTime,
			Protocol:     a.protocol,
		}
		logger.Info("Auth rate limiter: IP blocked (Tier 2)",
			"protocol", a.protocol,
			"ip", ip,
			"failure_count", info.FailureCount,
			"blocked_until", blockedUntil.Format(time.RFC3339))

		// Broadcast to cluster
		if a.clusterLimiter != nil {
			a.clusterLimiter.BroadcastBlockIP(ip, blockedUntil, info.FailureCount, a.protocol, info.FirstFailure)
		}
	} else if info.FailureCount >= a.config.DelayStartThreshold {
		logger.Debug("Auth limiter: Progressive delay for IP", "protocol", a.protocol, "ip", ip, "delay", info.LastDelay, "failures", info.FailureCount)

		// Broadcast failure count to cluster for progressive delays
		if a.clusterLimiter != nil {
			a.clusterLimiter.BroadcastFailureCount(ip, info.FailureCount, info.LastDelay, info.FirstFailure)
		}
	}
}

func (a *AuthRateLimiter) clearFailureTracking(ip string) {
	a.ipMu.Lock()
	delete(a.ipFailureCounts, ip)
	delete(a.blockedIPs, ip)
	a.ipMu.Unlock()
	logger.Debug("Auth limiter: Cleared failure tracking after successful login", "protocol", a.protocol, "ip", ip)
}

// updateIPUsernameFailure tracks IP+username authentication failures (Tier 1: fast blocking)
func (a *AuthRateLimiter) updateIPUsernameFailure(ip, username string, failureTime time.Time) {
	if username == "" || a.config.MaxAttemptsPerIPUsername == 0 {
		return // Skip if username empty or feature disabled
	}

	ipUsernameKey := ip + "|" + username
	a.ipUsernameMu.Lock()
	defer a.ipUsernameMu.Unlock()

	// Track failures for this IP+username combination
	var failureCount int
	if existing, exists := a.blockedIPUsernames[ipUsernameKey]; exists {
		failureCount = existing.FailureCount + 1
	} else {
		failureCount = 1
	}

	// Check if threshold reached
	if failureCount >= a.config.MaxAttemptsPerIPUsername {
		blockedUntil := failureTime.Add(a.config.IPUsernameBlockDuration)
		a.blockedIPUsernames[ipUsernameKey] = &BlockedIPUsernameInfo{
			BlockedUntil: blockedUntil,
			FailureCount: failureCount,
			FirstFailure: failureTime, // Approximate
			LastFailure:  failureTime,
			Protocol:     a.protocol,
			IP:           ip,
			Username:     username,
		}
		logger.Info("Auth rate limiter: IP+username blocked (Tier 1)",
			"protocol", a.protocol,
			"ip", ip,
			"username", username,
			"failure_count", failureCount,
			"blocked_until", blockedUntil.Format(time.RFC3339))

		// TODO: Broadcast to cluster
		if a.clusterLimiter != nil {
			// Future: Add BroadcastBlockIPUsername method
		}
	} else {
		// Update failure count even if not yet blocked
		if existing, exists := a.blockedIPUsernames[ipUsernameKey]; exists {
			existing.FailureCount = failureCount
			existing.LastFailure = failureTime
		} else {
			// Create tracking entry (not blocked yet)
			a.blockedIPUsernames[ipUsernameKey] = &BlockedIPUsernameInfo{
				FailureCount: failureCount,
				FirstFailure: failureTime,
				LastFailure:  failureTime,
				Protocol:     a.protocol,
				IP:           ip,
				Username:     username,
				BlockedUntil: time.Time{}, // Not blocked yet
			}
		}
	}
}

// clearIPUsernameFailure clears IP+username failure tracking after successful auth
func (a *AuthRateLimiter) clearIPUsernameFailure(ip, username string) {
	if username == "" {
		return
	}

	ipUsernameKey := ip + "|" + username
	a.ipUsernameMu.Lock()
	delete(a.blockedIPUsernames, ipUsernameKey)
	a.ipUsernameMu.Unlock()
}

// updateUsernameFailure tracks username authentication failures (cluster-synchronized)
func (a *AuthRateLimiter) updateUsernameFailure(username string, failureTime time.Time) {
	if username == "" {
		return // Skip empty usernames
	}

	a.usernameMu.Lock()
	defer a.usernameMu.Unlock()

	info, exists := a.usernameFailureCounts[username]
	if !exists {
		info = &UsernameFailureInfo{FirstFailure: failureTime}
		a.usernameFailureCounts[username] = info
	}

	info.FailureCount++
	info.LastFailure = failureTime

	// Broadcast to cluster
	if a.clusterLimiter != nil {
		a.clusterLimiter.BroadcastUsernameFailure(username)
	}
}

// clearUsernameFailure clears username failure tracking (cluster-synchronized)
func (a *AuthRateLimiter) clearUsernameFailure(username string) {
	if username == "" {
		return // Skip empty usernames
	}

	a.usernameMu.Lock()
	delete(a.usernameFailureCounts, username)
	a.usernameMu.Unlock()

	logger.Debug("Auth limiter: Cleared username failure tracking after successful login", "protocol", a.protocol, "username", username)

	// Broadcast to cluster
	if a.clusterLimiter != nil {
		a.clusterLimiter.BroadcastUsernameSuccess(username)
	}
}

// getUsernameFailureCount returns the number of failures for a username
func (a *AuthRateLimiter) getUsernameFailureCount(username string) int {
	if username == "" {
		return 0
	}

	a.usernameMu.RLock()
	defer a.usernameMu.RUnlock()

	if info, exists := a.usernameFailureCounts[username]; exists {
		return info.FailureCount
	}
	return 0
}

func (a *AuthRateLimiter) cleanupRoutine(interval time.Duration) {
	// Handle zero or negative interval (skip cleanup)
	if interval <= 0 {
		interval = 10 * time.Minute // Default to 10 minutes if not set
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.cleanupExpiredEntries()
		case <-a.stopCleanup:
			return
		}
	}
}

func (a *AuthRateLimiter) cleanupExpiredEntries() {
	now := time.Now()

	// Clean up expired IP+username blocks (Tier 1)
	a.ipUsernameMu.Lock()
	expiredIPUsernameBlocks := 0
	ipUsernameCutoff := now.Add(-a.config.IPUsernameWindowDuration)
	for key, blocked := range a.blockedIPUsernames {
		// Remove if block expired or entry is old
		if (!blocked.BlockedUntil.IsZero() && now.After(blocked.BlockedUntil)) || blocked.LastFailure.Before(ipUsernameCutoff) {
			delete(a.blockedIPUsernames, key)
			expiredIPUsernameBlocks++
		}
	}
	a.ipUsernameMu.Unlock()

	// Clean up expired IP blocks (Tier 2)
	a.ipMu.Lock()
	expiredBlocks := 0
	for ip, blocked := range a.blockedIPs {
		if now.After(blocked.BlockedUntil) {
			delete(a.blockedIPs, ip)
			expiredBlocks++
		}
	}
	a.ipMu.Unlock()

	// Clean up old IP failure tracking (Tier 2)
	a.ipMu.Lock()
	expiredFailures := 0
	ipCutoff := now.Add(-a.config.IPWindowDuration)
	for ip, info := range a.ipFailureCounts {
		if info.LastFailure.Before(ipCutoff) {
			delete(a.ipFailureCounts, ip)
			expiredFailures++
		}
	}
	a.ipMu.Unlock()

	// Clean up old username failure tracking (statistics only)
	a.usernameMu.Lock()
	expiredUsernames := 0
	usernameCutoff := now.Add(-a.config.UsernameWindowDuration)
	for username, info := range a.usernameFailureCounts {
		if info.LastFailure.Before(usernameCutoff) {
			delete(a.usernameFailureCounts, username)
			expiredUsernames++
		}
	}
	a.usernameMu.Unlock()

	if expiredIPUsernameBlocks > 0 || expiredBlocks > 0 || expiredFailures > 0 || expiredUsernames > 0 {
		logger.Debug("Auth limiter: Cleaned up expired entries", "protocol", a.protocol,
			"expired_ip_username_blocks", expiredIPUsernameBlocks,
			"expired_ip_blocks", expiredBlocks,
			"expired_ip_failures", expiredFailures,
			"expired_username_failures", expiredUsernames)
	}
}

func (a *AuthRateLimiter) GetStats(ctx context.Context, windowDuration time.Duration) map[string]any {
	if a == nil {
		return map[string]any{"enabled": false}
	}

	// Collect in-memory stats
	a.ipUsernameMu.RLock()
	blockedIPUsernameCount := len(a.blockedIPUsernames)
	a.ipUsernameMu.RUnlock()

	a.ipMu.RLock()
	blockedIPCount := len(a.blockedIPs)
	trackedIPs := len(a.ipFailureCounts)
	a.ipMu.RUnlock()

	a.usernameMu.RLock()
	trackedUsernames := len(a.usernameFailureCounts)
	a.usernameMu.RUnlock()

	stats := map[string]any{
		"enabled":              true,
		"blocked_ip_usernames": blockedIPUsernameCount, // Tier 1: IP+username blocks
		"blocked_ips":          blockedIPCount,         // Tier 2: IP-only blocks
		"tracked_ips":          trackedIPs,
		"tracked_usernames":    trackedUsernames,
		"cluster_enabled":      a.clusterLimiter != nil,
		"config": map[string]any{
			"max_attempts_per_ip_username": a.config.MaxAttemptsPerIPUsername,
			"ip_username_block_duration":   a.config.IPUsernameBlockDuration.String(),
			"ip_username_window_duration":  a.config.IPUsernameWindowDuration.String(),
			"max_attempts_per_ip":          a.config.MaxAttemptsPerIP,
			"ip_block_duration":            a.config.IPBlockDuration.String(),
			"ip_window_duration":           a.config.IPWindowDuration.String(),
			"max_attempts_per_username":    a.config.MaxAttemptsPerUsername,
			"username_window_duration":     a.config.UsernameWindowDuration.String(),
		},
	}

	return stats
}

func (a *AuthRateLimiter) Stop() {
	if a == nil {
		return
	}
	close(a.stopCleanup)
}
