package resilient

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/retry"
	"golang.org/x/crypto/bcrypt"
)

// --- AuthRateLimiter Wrappers ---

func (rd *ResilientDatabase) RecordAuthAttemptWithRetry(ctx context.Context, ipAddress, username, protocol string, success bool) error {
	config := retry.BackoffConfig{
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     500 * time.Millisecond,
		MaxRetries:      2,
	}
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).RecordAuthAttempt(ctx, tx, ipAddress, username, protocol, success)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, config, timeoutAuth, op)
	return err
}

func (rd *ResilientDatabase) GetFailedAttemptsCountSeparateWindowsWithRetry(ctx context.Context, ipAddress, username string, ipWindowDuration, usernameWindowDuration time.Duration) (ipCount, usernameCount int, err error) {
	config := retry.BackoffConfig{
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     500 * time.Millisecond,
		MaxRetries:      2,
	}
	op := func(ctx context.Context) (interface{}, error) {
		ip, user, dbErr := rd.getOperationalDatabaseForOperation(false).GetFailedAttemptsCountSeparateWindows(ctx, ipAddress, username, ipWindowDuration, usernameWindowDuration)
		if dbErr != nil {
			return nil, dbErr
		}
		return []int{ip, user}, nil
	}

	result, err := rd.executeReadWithRetry(ctx, config, timeoutAuth, op)
	if err != nil {
		return 0, 0, err
	}

	counts := result.([]int)
	return counts[0], counts[1], nil
}

// GetAuthAttemptsStats is not performance-critical and can be called directly for now.
// If it were used in a hot path, it would also be wrapped.
func (rd *ResilientDatabase) GetAuthAttemptsStats(ctx context.Context, windowDuration time.Duration) (map[string]interface{}, error) { // This is a direct call, not wrapped in retry logic.
	readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
	defer cancel()
	return rd.getOperationalDatabaseForOperation(false).GetAuthAttemptsStats(readCtx, windowDuration)
}

func (rd *ResilientDatabase) CleanupOldAuthAttemptsWithRetry(ctx context.Context, maxAge time.Duration) (int64, error) {
	// This is a background cleanup task, low priority, limited retries.
	config := retry.BackoffConfig{MaxRetries: 1}
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).CleanupOldAuthAttempts(ctx, tx, maxAge)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, config, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

// GetCredentialForAuthWithRetry retrieves credentials for authentication with retry logic
func (rd *ResilientDatabase) GetCredentialForAuthWithRetry(ctx context.Context, address string) (accountID int64, hashedPassword string, err error) {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
	}

	type credResult struct {
		ID   int64
		Hash string
	}

	op := func(ctx context.Context) (interface{}, error) {
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
		if cachedAccountID, found := rd.authCache.Authenticate(address, password); found {
			// Cache hit with successful authentication
			return cachedAccountID, nil
		}
		// Cache miss or auth failure - continue to database
	}

	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2, // Auth retries should be limited
	}

	type credResult struct {
		ID   int64
		Hash string
	}

	op := func(ctx context.Context) (interface{}, error) {
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
			rd.authCache.SetFailure(address, 1)
		}
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
			rd.authCache.SetFailure(address, 2)
		}
		return 0, err // Invalid password
	}

	// Cache successful authentication if enabled
	if rd.authCache != nil {
		rd.authCache.SetSuccess(address, accountID, hashedPassword)
	}

	// Asynchronously rehash if needed
	if db.NeedsRehash(hashedPassword) {
		go func() {
			newHash, hashErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if hashErr != nil {
				log.Printf("[REHASH] Failed to generate new hash for %s: %v", address, hashErr)
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
				log.Printf("[REHASH] Failed to update password for %s: %v", address, err)
			} else {
				log.Printf("[REHASH] Successfully rehashed and updated password for %s", address)
				// Invalidate cache entry since password hash changed
				if rd.authCache != nil {
					rd.authCache.Invalidate(address)
				}
			}
		}()
	}

	return accountID, nil
}
