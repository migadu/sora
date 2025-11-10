package resilient

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
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
