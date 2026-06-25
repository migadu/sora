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

// GetCredentialForAuthWithRetry retrieves credentials for authentication with retry logic.
// Used by backend servers (IMAP, POP3, ManageSieve) which have direct database access.
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
		id, hash, dbErr := rd.getOperationalDatabaseForOperation(ctx, false).GetCredentialForAuth(ctx, address)
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

// GetCredentialEpochWithRetry retrieves the account ID and the credential's
// password epoch (updated_at) for an address with retry logic, requiring the
// account to be active. The User API uses this to revalidate account state when
// refreshing a JWT — rejecting refreshes for deleted accounts or after a password
// change. See db.GetCredentialEpoch for the epoch semantics.
func (rd *ResilientDatabase) GetCredentialEpochWithRetry(ctx context.Context, address string) (accountID int64, epoch time.Time, err error) {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
		OperationName:   "db_credential_epoch",
	}

	type epochResult struct {
		ID    int64
		Epoch time.Time
	}

	op := func(ctx context.Context) (any, error) {
		id, ep, dbErr := rd.getOperationalDatabaseForOperation(ctx, false).GetCredentialEpoch(ctx, address)
		if dbErr != nil {
			return nil, dbErr
		}
		return epochResult{ID: id, Epoch: ep}, nil
	}

	result, err := rd.executeReadWithRetry(ctx, config, timeoutAuth, op, consts.ErrUserNotFound)
	if err != nil {
		return 0, time.Time{}, err
	}

	res := result.(epochResult)
	return res.ID, res.Epoch, nil
}

// AuthenticateWithRetry handles the full authentication flow with resilience.
// It fetches credentials from PostgreSQL, verifies the password, and triggers
// a rehash if necessary.
//
// SCOPE: This method is ONLY for PostgreSQL database lookups. It is NOT used
// for remote lookup authentication (which is handled by the proxy's connection
// manager). Proxy servers call this method only in the "fallback to main DB"
// code path — either when remote lookup is not configured, or when remote
// lookup returns "user not found" and lookup_local_users is enabled.
//
// AUTH RATE LIMITING: This method does not perform any rate limiting. Rate
// limiting is handled by the proxy server layer (authLimiter) which records
// success/failure AFTER this method returns. The auth cache is transparent
// to the rate limiter.
//
// AUTH CACHE BEHAVIOR (when enabled via SetAuthCache):
//  1. Check the local SQLite cache first (~0.1ms)
//  2. On cache hit + password matches: return success (no DB round-trip)
//  3. On cache hit + password mismatch: invalidate stale entry, fall through to DB
//  4. On cache miss: fall through to DB
//  5. On successful DB auth: cache the credentials for future use
//
// This eliminates the "thundering herd" problem on proxy restart where thousands
// of clients reconnect simultaneously.
func (rd *ResilientDatabase) AuthenticateWithRetry(ctx context.Context, address, password string) (accountID int64, err error) {
	// --- Step 1: Try persistent auth cache (if enabled) ---
	// The cache is ONLY populated from successful DB lookups, never from remote lookups.
	if rd.authCache != nil {
		cachedAccountID, cachedHash, cacheErr := rd.authCache.Get(ctx, address)
		if cacheErr == nil {
			// Cache hit — verify password locally using the cached hash
			if verifyErr := db.VerifyPassword(cachedHash, password); verifyErr == nil {
				// Password matches cached hash — no database round-trip needed
				return cachedAccountID, nil
			}
			// Password mismatch — the password may have changed since caching.
			// Invalidate the stale entry and fall through to the authoritative DB.
			rd.authCache.Invalidate(ctx, address)
		}
		// Cache miss or cache error — proceed to PostgreSQL
	}

	// --- Step 2: Fetch credentials from PostgreSQL ---
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
		id, hash, dbErr := rd.getOperationalDatabaseForOperation(ctx, false).GetCredentialForAuth(ctx, address)
		if dbErr != nil {
			return nil, dbErr
		}
		return credResult{ID: id, Hash: hash}, nil
	}

	result, err := rd.executeReadWithRetry(ctx, config, timeoutAuth, op, consts.ErrUserNotFound)
	if err != nil {
		// NOTE: No logging here - let the calling server log with proper context
		return 0, err // Return error from fetching credentials
	}

	cred := result.(credResult)
	accountID = cred.ID
	hashedPassword := cred.Hash

	// --- Step 3: Verify password ---
	if err := db.VerifyPassword(hashedPassword, password); err != nil {
		// NOTE: No logging here - let the calling server log with proper context
		// (protocol, server name, cached status, etc)
		return 0, err // Invalid password
	}

	// NOTE: No logging here - let the calling server log with proper context
	// Backend servers log with cache=hit/miss, proxy servers log with method and cached status

	// --- Step 4: Cache successful authentication (async, non-blocking) ---
	if rd.authCache != nil {
		go func() {
			cacheCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if putErr := rd.authCache.Put(cacheCtx, address, accountID, hashedPassword); putErr != nil {
				logger.Warn("AuthCache: Failed to cache credentials", "address", address, "error", putErr)
			}
		}()
	}

	// --- Step 5: Asynchronously rehash if needed ---
	if db.NeedsRehash(hashedPassword) {
		go func() {
			newHash, hashErr := bcrypt.GenerateFromPassword([]byte(password), db.BcryptCost)
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

				// Update the auth cache with the new hash
				if rd.authCache != nil {
					cacheCtx, cacheCancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cacheCancel()
					rd.authCache.Put(cacheCtx, address, accountID, newHashedPassword)
				}
			}
		}()
	}

	return accountID, nil
}
