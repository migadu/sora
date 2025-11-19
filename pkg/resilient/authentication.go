package resilient

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/retry"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// GetCredentialForAuthWithRetry retrieves credentials for authentication with retry logic
func (rd *ResilientDatabase) GetCredentialForAuthWithRetry(ctx context.Context, address string) (accountID int64, hashedPassword string, err error) {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
		OperationName:   "db_auth_credential",
	}

	type credResult struct {
		ID   int64
		Hash string
	}

	op := func(ctx context.Context) (any, error) {
		id, hash, dbErr := rd.getOperationalDatabaseForOperation(false).GetCredentialForAuth(ctx, address)
		if dbErr != nil {
			return nil, dbErr
		}
		return credResult{ID: id, Hash: hash}, nil
	}

	result, err := rd.executeReadWithRetry(ctx, config, timeoutAuth, op, consts.ErrUserNotFound)
	if err != nil {
		return 0, "", err
	}

	cred := result.(credResult)
	return cred.ID, cred.Hash, nil
}

// AuthenticateWithRetry handles the full authentication flow with resilience.
// It fetches credentials, verifies the password, and triggers a rehash if necessary.
// Uses authentication cache if enabled to reduce database load.
func (rd *ResilientDatabase) AuthenticateWithRetry(ctx context.Context, address, password string) (accountID int64, err error) {
	// Check auth cache first if enabled
	if rd.authCache != nil {
		cachedAccountID, found, cacheErr := rd.authCache.Authenticate(address, password)
		if cacheErr != nil {
			// Cached authentication failure - return immediately without querying database
			return 0, cacheErr
		}
		if found {
			// Cache hit with successful authentication
			logger.Info("Authentication successful", "address", address, "account_id", cachedAccountID, "cache", "hit")
			return cachedAccountID, nil
		}
		// Cache miss - continue to database
		logger.Debug("Authentication: cache miss, checking database", "address", address)
	}

	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2, // Auth retries should be limited
		OperationName:   "db_authenticate",
	}

	type credResult struct {
		ID   int64
		Hash string
	}

	op := func(ctx context.Context) (any, error) {
		id, hash, dbErr := rd.getOperationalDatabaseForOperation(false).GetCredentialForAuth(ctx, address)
		if dbErr != nil {
			return nil, dbErr
		}
		return credResult{ID: id, Hash: hash}, nil
	}

	result, err := rd.executeReadWithRetry(ctx, config, timeoutAuth, op, consts.ErrUserNotFound)
	if err != nil {
		// Cache negative result if enabled
		if rd.authCache != nil {
			// AuthUserNotFound = 1 (from authcache package)
			rd.authCache.SetFailure(address, 1, password)
		}
		logger.Info("Authentication failed", "address", address, "error", err, "cache", "miss")
		return 0, err // Return error from fetching credentials
	}

	cred := result.(credResult)
	accountID = cred.ID
	hashedPassword := cred.Hash

	// Verify password
	if err := db.VerifyPassword(hashedPassword, password); err != nil {
		// Cache negative result for invalid password if enabled
		if rd.authCache != nil {
			// AuthInvalidPassword = 2 (from authcache package)
			rd.authCache.SetFailure(address, 2, password)
		}
		logger.Info("Authentication failed", "address", address, "error", "invalid password", "cache", "miss")
		return 0, err // Invalid password
	}

	// Cache successful authentication if enabled
	if rd.authCache != nil {
		rd.authCache.SetSuccess(address, accountID, hashedPassword, password)
	}

	logger.Info("Authentication successful", "address", address, "account_id", accountID, "cache", "miss")

	// Asynchronously rehash if needed
	if db.NeedsRehash(hashedPassword) {
		go func() {
			newHash, hashErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if hashErr != nil {
				logger.Error("Rehash: Failed to generate new hash", "address", address, "error", hashErr)
				return
			}

			// If it's a BLF-CRYPT format, preserve the prefix
			var newHashedPassword string
			if strings.HasPrefix(hashedPassword, "{BLF-CRYPT}") {
				newHashedPassword = "{BLF-CRYPT}" + string(newHash)
			} else {
				newHashedPassword = string(newHash)
			}

			// Use the configured write timeout for this background task.
			// We create a new context because the original request context may have expired.
			updateCtx, cancel := rd.withTimeout(context.Background(), timeoutWrite)
			defer cancel()

			// Use a new resilient call for the update
			if err := rd.UpdatePasswordWithRetry(updateCtx, address, newHashedPassword); err != nil {
				logger.Error("Rehash: Failed to update password", "address", address, "error", err)
			} else {
				logger.Info("Rehash: Successfully rehashed and updated password", "address", address)
				// Invalidate cache entry since password hash changed
				if rd.authCache != nil {
					rd.authCache.Invalidate(address)
				}
			}
		}()
	}

	return accountID, nil
}

// InitializeAuthCache is a helper function for backend servers (IMAP, POP3, ManageSieve)
// to initialize authentication cache with consistent logging and configuration handling.
//
// This centralizes the common auth cache initialization logic that would otherwise be
// duplicated across all backend server implementations.
//
// Parameters:
//   - protocol: Protocol name for logging (e.g., "IMAP", "POP3", "ManageSieve")
//   - serverName: Server name for logging
//   - lookupCacheConfig: Auth cache configuration from server config (can be nil, defaults will be applied)
//   - rdb: ResilientDatabase instance to set the cache on
//
// The function applies default configuration if lookupCacheConfig is nil, parses TTL durations with fallback
// to defaults, creates the auth cache, and sets it on the ResilientDatabase instance.
func InitializeAuthCache(protocol string, serverName string, lookupCacheConfig *config.LookupCacheConfig, rdb *ResilientDatabase) {
	// Apply defaults if not configured (enabled by default for performance)
	if lookupCacheConfig == nil {
		defaultConfig := config.DefaultLookupCacheConfig()
		lookupCacheConfig = &defaultConfig
	}

	if !lookupCacheConfig.Enabled {
		logger.Info(protocol+": Authentication cache disabled", "name", serverName)
		return
	}

	// Parse positive TTL with fallback to default
	positiveTTL, err := time.ParseDuration(lookupCacheConfig.PositiveTTL)
	if err != nil || lookupCacheConfig.PositiveTTL == "" {
		logger.Info(protocol+": Using default positive TTL (5m)", "name", serverName)
		positiveTTL = 5 * time.Minute
	}

	// Parse negative TTL with fallback to default
	negativeTTL, err := time.ParseDuration(lookupCacheConfig.NegativeTTL)
	if err != nil || lookupCacheConfig.NegativeTTL == "" {
		logger.Info(protocol+": Using default negative TTL (1m)", "name", serverName)
		negativeTTL = 1 * time.Minute
	}

	// Parse cleanup interval with fallback to default
	cleanupInterval, err := time.ParseDuration(lookupCacheConfig.CleanupInterval)
	if err != nil || lookupCacheConfig.CleanupInterval == "" {
		logger.Info(protocol+": Using default cleanup interval (5m)", "name", serverName)
		cleanupInterval = 5 * time.Minute
	}

	// Get max size with fallback to default
	maxSize := lookupCacheConfig.MaxSize
	if maxSize == 0 {
		maxSize = 10000
	}

	// Parse positive revalidation window from config
	positiveRevalidationWindow, err := lookupCacheConfig.GetPositiveRevalidationWindow()
	if err != nil {
		logger.Info(protocol+": Invalid positive revalidation window in auth cache config, using default (30s)", "name", serverName, "error", err)
		positiveRevalidationWindow = 30 * time.Second
	}

	// Create auth cache and set it on ResilientDatabase
	cache := lookupcache.New(positiveTTL, negativeTTL, maxSize, cleanupInterval, positiveRevalidationWindow)
	rdb.SetAuthCache(cache)
	logger.Info(protocol+": Authentication cache enabled", "name", serverName, "positive_ttl", positiveTTL, "negative_ttl", negativeTTL, "max_size", maxSize,
		"positive_revalidation_window", positiveRevalidationWindow)
}
