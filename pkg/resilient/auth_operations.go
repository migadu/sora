package resilient

import (
	"context"
	"errors"
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
	// This is a high-frequency write operation. Retries should be short.
	config := retry.BackoffConfig{
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     500 * time.Millisecond,
		MaxRetries:      2,
	}
	return retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		// Apply auth-specific timeout for authentication logging
		authCtx, cancel := rd.withTimeout(ctx, timeoutAuth)
		defer cancel()

		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabaseForOperation(true).RecordAuthAttempt(authCtx, tx, ipAddress, username, protocol, success)
		})
		if cbErr != nil && !rd.isRetryableError(cbErr) {
			return retry.Stop(cbErr)
		}

		if err := tx.Commit(ctx); err != nil {
			return err
		}

		return cbErr
	}, config)
}

func (rd *ResilientDatabase) GetFailedAttemptsCountSeparateWindowsWithRetry(ctx context.Context, ipAddress, username string, ipWindowDuration, usernameWindowDuration time.Duration) (ipCount, usernameCount int, err error) {
	// This is a read operation used for security checks. Retries should be short.
	config := retry.BackoffConfig{
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     500 * time.Millisecond,
		MaxRetries:      2,
	}
	err = retry.WithRetry(ctx, func() error {
		// Apply auth-specific timeout for security operations
		authCtx, cancel := rd.withTimeout(ctx, timeoutAuth)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			ip, user, dbErr := rd.getOperationalDatabaseForOperation(false).GetFailedAttemptsCountSeparateWindows(authCtx, ipAddress, username, ipWindowDuration, usernameWindowDuration)
			if dbErr != nil {
				return nil, dbErr
			}
			return []int{ip, user}, nil
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		counts := result.([]int)
		ipCount = counts[0]
		usernameCount = counts[1]
		return nil
	}, config)
	return ipCount, usernameCount, err
}

// GetAuthAttemptsStats is not performance-critical and can be called directly for now.
// If it were used in a hot path, it would also be wrapped.
func (rd *ResilientDatabase) GetAuthAttemptsStats(ctx context.Context, windowDuration time.Duration) (map[string]interface{}, error) { // This is a direct call, not wrapped in retry logic.
	readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
	defer cancel()
	return rd.getOperationalDatabaseForOperation(false).GetAuthAttemptsStats(readCtx, windowDuration)
}

func (rd *ResilientDatabase) CleanupOldAuthAttemptsWithRetry(ctx context.Context, maxAge time.Duration) (int64, error) {
	// This is a background cleanup task, low priority, no retries needed.
	config := retry.BackoffConfig{MaxRetries: 1}
	var count int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		writeCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
		defer cancel()

		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(true).CleanupOldAuthAttempts(writeCtx, tx, maxAge)
		})
		if cbErr != nil {
			return retry.Stop(cbErr)
		}

		if err := tx.Commit(ctx); err != nil {
			return err
		}

		count = result.(int64)
		return nil
	}, config)
	return count, err
}

// AuthenticateWithRetry handles the full authentication flow with resilience.
// It fetches credentials, verifies the password, and triggers a rehash if necessary.
func (rd *ResilientDatabase) AuthenticateWithRetry(ctx context.Context, address, password string) (accountID int64, err error) {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2, // Auth retries should be limited
	}

	var hashedPassword string
	err = retry.WithRetry(ctx, func() error {
		queryCtx, cancel := rd.withTimeout(ctx, timeoutAuth)
		defer cancel()

		// Define a struct to hold the multiple return values from GetCredentialForAuth
		type credResult struct {
			ID   int64
			Hash string
		}

		// Authentication is a critical read path. Use queryBreaker.
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			id, hash, dbErr := rd.getOperationalDatabaseForOperation(false).GetCredentialForAuth(queryCtx, address)
			if dbErr != nil {
				return nil, dbErr
			}
			return credResult{ID: id, Hash: hash}, nil
		})

		if cbErr != nil {
			// Don't retry on auth errors (user not found), only on connection errors.
			if errors.Is(cbErr, consts.ErrUserNotFound) {
				return retry.Stop(cbErr)
			}
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			log.Printf("Retrying credential fetch for %s due to retryable error: %v", address, cbErr)
			return cbErr
		}

		// Unpack results
		cred := result.(credResult)
		accountID = cred.ID
		hashedPassword = cred.Hash
		return nil
	}, config)

	if err != nil {
		return 0, err // Return error from fetching credentials
	}

	// Verify password
	if err := db.VerifyPassword(hashedPassword, password); err != nil {
		return 0, err // Invalid password
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
			}
		}()
	}

	return accountID, nil
}
