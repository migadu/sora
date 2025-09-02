package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

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

// AuthRateLimiterConfig holds authentication rate limiting configuration
type AuthRateLimiterConfig struct {
	MaxAttemptsPerIP       int           `toml:"max_attempts_per_ip"`       // Max failed attempts per IP
	MaxAttemptsPerUsername int           `toml:"max_attempts_per_username"` // Max failed attempts per username
	IPWindowDuration       time.Duration `toml:"ip_window_duration"`       // Time window for IP-based limiting
	UsernameWindowDuration time.Duration `toml:"username_window_duration"`  // Time window for username-based limiting
	CleanupInterval        time.Duration `toml:"cleanup_interval"`          // How often to clean up old entries
	Enabled                bool          `toml:"enabled"`                   // Enable/disable rate limiting
}

// DefaultAuthRateLimiterConfig returns sensible defaults
func DefaultAuthRateLimiterConfig() AuthRateLimiterConfig {
	return AuthRateLimiterConfig{
		MaxAttemptsPerIP:       10,                // 10 failed attempts per IP
		MaxAttemptsPerUsername: 5,                 // 5 failed attempts per username  
		IPWindowDuration:       15 * time.Minute, // 15 minute window for IP
		UsernameWindowDuration: 30 * time.Minute, // 30 minute window for username
		CleanupInterval:        5 * time.Minute,  // Clean up every 5 minutes
		Enabled:                false,             // Disabled by default
	}
}

// AuthAttempt represents a single authentication attempt
type AuthAttempt struct {
	Timestamp time.Time
	Success   bool
	IP        string
	Username  string
}

// AuthRateLimiter manages authentication rate limiting
type AuthRateLimiter struct {
	config           AuthRateLimiterConfig
	ipAttempts       map[string][]AuthAttempt // Kept for compatibility with existing code
	usernameAttempts map[string][]AuthAttempt // Kept for compatibility with existing code
	db               AuthDatabase             // Database for shared storage
	mu               sync.RWMutex
	protocol         string
	stopCleanup      chan struct{}
}

// GetAuthenticationDelay returns 0 for basic rate limiter (no delays)
// This implements the AuthDelayHelper interface
func (a *AuthRateLimiter) GetAuthenticationDelay(remoteAddr net.Addr) time.Duration {
	return 0 // Basic rate limiter doesn't implement delays
}

// AuthDatabase interface for rate limiting database operations
type AuthDatabase interface {
	RecordAuthAttempt(ctx context.Context, ipAddress, username, protocol string, success bool) error
	GetFailedAttemptsCountSeparateWindows(ctx context.Context, ipAddress, username string, ipWindowDuration, usernameWindowDuration time.Duration) (ipCount, usernameCount int, err error)
	CleanupOldAuthAttempts(ctx context.Context, maxAge time.Duration) (int64, error)
	GetAuthAttemptsStats(ctx context.Context, windowDuration time.Duration) (map[string]interface{}, error)
}

// AuthLimiter interface that both AuthRateLimiter and EnhancedAuthRateLimiter implement
type AuthLimiter interface {
	CanAttemptAuth(ctx context.Context, remoteAddr net.Addr, username string) error
	RecordAuthAttempt(ctx context.Context, remoteAddr net.Addr, username string, success bool)
	GetStats(ctx context.Context, windowDuration time.Duration) map[string]interface{}
	Stop()
}

// NewAuthRateLimiter creates a new authentication rate limiter
func NewAuthRateLimiter(protocol string, config AuthRateLimiterConfig, database AuthDatabase) *AuthRateLimiter {
	if !config.Enabled {
		return nil
	}

	limiter := &AuthRateLimiter{
		config:           config,
		ipAttempts:       make(map[string][]AuthAttempt), // Initialize for compatibility
		usernameAttempts: make(map[string][]AuthAttempt), // Initialize for compatibility
		db:               database,
		protocol:         protocol,
		stopCleanup:      make(chan struct{}),
	}

	// Start cleanup routine
	go limiter.cleanupRoutine()

	log.Printf("[%s-AUTH-LIMITER] Initialized with database backend: max_per_ip=%d/%v, max_per_user=%d/%v", 
		protocol, config.MaxAttemptsPerIP, config.IPWindowDuration,
		config.MaxAttemptsPerUsername, config.UsernameWindowDuration)

	return limiter
}

// CanAttemptAuth checks if authentication can be attempted from the given IP and username
func (a *AuthRateLimiter) CanAttemptAuth(ctx context.Context, remoteAddr net.Addr, username string) error {
	if a == nil {
		return nil // Rate limiting disabled
	}

	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	// Get failed attempts count from database
	ipCount, usernameCount, err := a.db.GetFailedAttemptsCountSeparateWindows(ctx, ip, username, a.config.IPWindowDuration, a.config.UsernameWindowDuration)
	if err != nil {
		log.Printf("[%s-AUTH-LIMITER] Warning: failed to check rate limits: %v", a.protocol, err)
		// On database error, allow the attempt (fail open)
		return nil
	}

	// Check IP-based rate limiting
	if a.config.MaxAttemptsPerIP > 0 && ipCount >= a.config.MaxAttemptsPerIP {
		return fmt.Errorf("too many failed authentication attempts from IP %s (%d/%d in %v)", 
			ip, ipCount, a.config.MaxAttemptsPerIP, a.config.IPWindowDuration)
	}

	// Check username-based rate limiting
	if a.config.MaxAttemptsPerUsername > 0 && username != "" && usernameCount >= a.config.MaxAttemptsPerUsername {
		return fmt.Errorf("too many failed authentication attempts for user %s (%d/%d in %v)", 
			username, usernameCount, a.config.MaxAttemptsPerUsername, a.config.UsernameWindowDuration)
	}

	return nil
}

// RecordAuthAttempt records an authentication attempt (success or failure)
func (a *AuthRateLimiter) RecordAuthAttempt(ctx context.Context, remoteAddr net.Addr, username string, success bool) {
	if a == nil {
		return // Rate limiting disabled
	}

	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	// Record attempt in database
	err = a.db.RecordAuthAttempt(ctx, ip, username, a.protocol, success)
	if err != nil {
		log.Printf("[%s-AUTH-LIMITER] Warning: failed to record auth attempt: %v", a.protocol, err)
		// Continue execution even if recording fails
	}

	if !success {
		log.Printf("[%s-AUTH-LIMITER] Failed authentication attempt from %s for user '%s'", 
			a.protocol, ip, username)
	}
}

// countRecentFailures counts failed attempts within the specified time window
func (a *AuthRateLimiter) countRecentFailures(attempts []AuthAttempt, now time.Time, window time.Duration) int {
	count := 0
	cutoff := now.Add(-window)
	
	for _, attempt := range attempts {
		if attempt.Timestamp.After(cutoff) && !attempt.Success {
			count++
		}
	}
	
	return count
}

// cleanupRoutine periodically removes old authentication attempts
func (a *AuthRateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(a.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.cleanup()
		case <-a.stopCleanup:
			return
		}
	}
}

// cleanup removes old authentication attempts from the database
func (a *AuthRateLimiter) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Calculate the maximum retention period (take the longer of the two windows plus some buffer)
	maxRetention := a.config.IPWindowDuration
	if a.config.UsernameWindowDuration > maxRetention {
		maxRetention = a.config.UsernameWindowDuration
	}
	// Add buffer time to ensure we don't delete records that might still be needed
	maxRetention = maxRetention * 2

	rowsDeleted, err := a.db.CleanupOldAuthAttempts(ctx, maxRetention)
	if err != nil {
		log.Printf("[%s-AUTH-LIMITER] Warning: cleanup failed: %v", a.protocol, err)
		return
	}

	if rowsDeleted > 0 {
		log.Printf("[%s-AUTH-LIMITER] Cleaned up %d old authentication attempts", 
			a.protocol, rowsDeleted)
	}
}

// GetStats returns current rate limiting statistics
func (a *AuthRateLimiter) GetStats(ctx context.Context, windowDuration time.Duration) map[string]interface{} {
	if a == nil {
		return map[string]interface{}{"enabled": false}
	}

	// Get stats from database
	stats, err := a.db.GetAuthAttemptsStats(ctx, windowDuration)
	if err != nil {
		log.Printf("[%s-AUTH-LIMITER] Warning: failed to get stats: %v", a.protocol, err)
		return map[string]interface{}{
			"enabled": true,
			"error":   "failed to get stats from database",
			"config": map[string]interface{}{
				"max_attempts_per_ip":       a.config.MaxAttemptsPerIP,
				"max_attempts_per_username": a.config.MaxAttemptsPerUsername,
				"ip_window_duration":        a.config.IPWindowDuration.String(),
				"username_window_duration":  a.config.UsernameWindowDuration.String(),
			},
		}
	}

	stats["enabled"] = true
	stats["storage"] = "database"
	stats["config"] = map[string]interface{}{
		"max_attempts_per_ip":       a.config.MaxAttemptsPerIP,
		"max_attempts_per_username": a.config.MaxAttemptsPerUsername,
		"ip_window_duration":        a.config.IPWindowDuration.String(),
		"username_window_duration":  a.config.UsernameWindowDuration.String(),
	}

	return stats
}

// Stop shuts down the rate limiter
func (a *AuthRateLimiter) Stop() {
	if a == nil {
		return
	}
	close(a.stopCleanup)
}