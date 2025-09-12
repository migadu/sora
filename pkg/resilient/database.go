package resilient

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/retry"
	"github.com/migadu/sora/server"
	"golang.org/x/crypto/bcrypt"
)

// DatabasePool represents a single database connection pool with health tracking
type DatabasePool struct {
	database    *db.Database
	host        string
	isHealthy   atomic.Bool
	lastFailure atomic.Int64 // Unix timestamp
	failCount   atomic.Int64
	mu          sync.RWMutex
}

// RuntimeFailoverManager manages multiple database pools and handles failover
type RuntimeFailoverManager struct {
	writePools      []*DatabasePool
	readPools       []*DatabasePool
	currentWriteIdx atomic.Int64
	currentReadIdx  atomic.Int64
	config          *config.DatabaseConfig
	healthCheckStop chan struct{}
	mu              sync.RWMutex
}

// readPoolsAreDistinct checks if the read pools are a separate set from the write pools.
func (fm *RuntimeFailoverManager) readPoolsAreDistinct() bool {
	// If there are no read pools or no write pools, they can't be distinct.
	if len(fm.readPools) == 0 || len(fm.writePools) == 0 {
		return false
	}
	// Slices are distinct if their first elements' memory addresses are different.
	return &fm.readPools[0] != &fm.writePools[0]
}

type ResilientDatabase struct {
	// Runtime failover support
	failoverManager *RuntimeFailoverManager

	// Circuit breakers (per-operation type)
	queryBreaker *circuitbreaker.CircuitBreaker
	writeBreaker *circuitbreaker.CircuitBreaker
}

func NewResilientDatabase(ctx context.Context, config *config.DatabaseConfig, enableHealthCheck bool, runMigrations bool) (*ResilientDatabase, error) {
	// Create circuit breakers
	querySettings := circuitbreaker.DefaultSettings("database_query")
	querySettings.MaxRequests = 5
	querySettings.Interval = 15 * time.Second
	querySettings.Timeout = 45 * time.Second
	querySettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 8 && failureRatio >= 0.6
	}
	querySettings.OnStateChange = func(name string, from circuitbreaker.State, to circuitbreaker.State) {
		log.Printf("[RESILIENT-FAILOVER] Database query circuit breaker '%s' changed from %s to %s", name, from, to)
	}

	writeSettings := circuitbreaker.DefaultSettings("database_write")
	writeSettings.MaxRequests = 3
	writeSettings.Interval = 10 * time.Second
	writeSettings.Timeout = 30 * time.Second
	writeSettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 5 && failureRatio >= 0.5
	}
	writeSettings.OnStateChange = func(name string, from circuitbreaker.State, to circuitbreaker.State) {
		log.Printf("[RESILIENT-FAILOVER] Database write circuit breaker '%s' changed from %s to %s", name, from, to)
	}

	// Create failover manager
	failoverManager, err := newRuntimeFailoverManager(ctx, config, runMigrations)
	if err != nil {
		return nil, fmt.Errorf("failed to create failover manager: %w", err)
	}

	rdb := &ResilientDatabase{
		failoverManager: failoverManager,
		queryBreaker:    circuitbreaker.NewCircuitBreaker(querySettings),
		writeBreaker:    circuitbreaker.NewCircuitBreaker(writeSettings),
	}

	// Start background health checking if enabled
	if enableHealthCheck {
		go rdb.startRuntimeHealthChecking(ctx)
	}

	return rdb, nil
}

func (rd *ResilientDatabase) GetDatabase() *db.Database {
	return rd.getCurrentDatabase()
}

// isRetryableError checks if an error is transient and the operation can be retried.
// It uses type assertions and error codes for robust checking.
func (rd *ResilientDatabase) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Do not retry if the circuit breaker is open or the context is done.
	if errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) ||
		errors.Is(err, circuitbreaker.ErrTooManyRequests) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// Check for PostgreSQL error codes that indicate transient issues.
		// See: https://www.postgresql.org/docs/current/errcodes-appendix.html
		switch pgErr.Code {
		// Class 40: Transaction Rollback (e.g., deadlock, serialization failure)
		case "40001", "40P01":
			return true
		// Class 53: Insufficient Resources (e.g., too many connections)
		case "53300":
			return true
		// Class 08: Connection Exception
		case "08000", "08001", "08003", "08004", "08006", "08007", "08P01":
			return true
		}
	}

	// Check for generic network errors that are temporary
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return false
}

func (rd *ResilientDatabase) QueryWithRetry(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	// Determine if this should go to write or read pools
	var pool *pgxpool.Pool

	if useMaster, ok := ctx.Value(consts.UseMasterDBKey).(bool); ok && useMaster {
		// Explicitly requested to use master/write database
		db := rd.getOperationalDatabaseForOperation(true)
		pool = db.WritePool
	} else {
		// Use read database for queries by default
		db := rd.getOperationalDatabaseForOperation(false)
		pool = db.ReadPool
	}

	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     5 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
	}

	var rows pgx.Rows
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			r, queryErr := pool.Query(ctx, sql, args...)
			return r, queryErr
		})

		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				// For non-retryable errors, we'll break the retry loop by returning nil from WithRetry
				// and handle the error outside
				return cbErr
			}
			log.Printf("Retrying query due to retryable error: %v", cbErr)
			return cbErr // It's retryable, so return the error to signal a retry.
		}

		rows = result.(pgx.Rows)
		return nil
	}, config)

	return rows, err
}

// resilientRow implements the pgx.Row interface to defer the Scan operation
// and execute it within the retry and circuit breaker logic.
type resilientRow struct {
	ctx    context.Context
	rd     *ResilientDatabase
	sql    string
	args   []interface{}
	config retry.BackoffConfig
}

// Scan executes the query and scans the result. This is where the retry and
// circuit breaker logic is actually applied for the query.
func (r *resilientRow) Scan(dest ...interface{}) error {
	var scanErr error

	// The retry logic will re-execute this function upon failure.
	retryErr := retry.WithRetryAdvanced(r.ctx, func() error {
		// The circuit breaker protects each individual attempt.
		_, cbErr := r.rd.queryBreaker.Execute(func() (interface{}, error) {
			var pool *pgxpool.Pool
			if useMaster, ok := r.ctx.Value(consts.UseMasterDBKey).(bool); ok && useMaster {
				db := r.rd.getOperationalDatabaseForOperation(true)
				pool = db.WritePool
			} else {
				db := r.rd.getOperationalDatabaseForOperation(false)
				// For a db.Database object representing a single host, WritePool and ReadPool are the same.
				// We use ReadPool for semantic clarity.
				pool = db.ReadPool
			}

			scanErr = pool.QueryRow(r.ctx, r.sql, r.args...).Scan(dest...)

			// pgx.ErrNoRows is an expected outcome, not a system failure.
			// We treat it as a success for the circuit breaker so it doesn't trip.
			if scanErr != nil && !errors.Is(scanErr, pgx.ErrNoRows) {
				return nil, scanErr // A real error occurred.
			}
			return nil, nil // Success (or ErrNoRows).
		})

		// If the circuit breaker returns an error, check if it's retryable.
		if cbErr != nil {
			if r.rd.isRetryableError(cbErr) {
				log.Printf("Retrying QueryRow due to retryable error: %v", cbErr)
				return cbErr // Signal to retry.WithRetry to try again.
			}
			// It's a non-retryable error (e.g., circuit open), so stop retrying.
			return retry.Stop(cbErr)
		}

		// If the circuit breaker reported success, we don't need to retry.
		return nil
	}, r.config)

	// If retry.WithRetry failed after all attempts, it returns the last error.
	if retryErr != nil {
		return retryErr
	}

	// Otherwise, the operation succeeded. The result of Scan is in scanErr.
	return scanErr
}

func (rd *ResilientDatabase) QueryRowWithRetry(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     3 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
	}
	return &resilientRow{ctx: ctx, rd: rd, sql: sql, args: args, config: config}
}

func (rd *ResilientDatabase) ExecWithRetry(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	config := retry.BackoffConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     10 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      2,
	}

	var tag pgconn.CommandTag
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			t, execErr := rd.getOperationalDatabase().WritePool.Exec(ctx, sql, args...)
			return t, execErr
		})

		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			log.Printf("Retrying exec due to retryable error: %v", cbErr)
			return cbErr
		}

		tag = result.(pgconn.CommandTag)
		return nil
	}, config)

	return tag, err
}

func (rd *ResilientDatabase) BeginTxWithRetry(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error) {
	config := retry.BackoffConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     5 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      2,
	}

	var tx pgx.Tx
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			t, txErr := rd.getOperationalDatabase().WritePool.BeginTx(ctx, txOptions)
			return t, txErr
		})

		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			log.Printf("Retrying BeginTx due to retryable error: %v", cbErr)
			return cbErr
		}

		tx = result.(pgx.Tx)
		return nil
	}, config)

	return tx, err
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
		// Define a struct to hold the multiple return values from GetCredentialForAuth
		type credResult struct {
			ID   int64
			Hash string
		}

		// Authentication is a critical read path. Use queryBreaker.
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			id, hash, dbErr := rd.getOperationalDatabase().GetCredentialForAuth(ctx, address)
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

			updateCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

// UpdatePasswordWithRetry updates a user's password with resilience.
func (rd *ResilientDatabase) UpdatePasswordWithRetry(ctx context.Context, address, newHashedPassword string) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
	}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().UpdatePassword(ctx, address, newHashedPassword)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, config)
}

// GetLastServerAddressWithRetry retrieves the last server address a user connected to, with retry logic.
func (rd *ResilientDatabase) GetLastServerAddressWithRetry(ctx context.Context, accountID int64) (string, time.Time, error) {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      3,
	}

	var lastAddr string
	var lastTime time.Time

	err := retry.WithRetryAdvanced(ctx, func() error {
		// This is a read operation.
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			addr, t, err := rd.getOperationalDatabase().GetLastServerAddress(ctx, accountID)
			if err != nil {
				return nil, err
			}
			return []interface{}{addr, t}, nil
		})

		if cbErr != nil {
			if errors.Is(cbErr, db.ErrNoServerAffinity) {
				return retry.Stop(cbErr) // Not a retryable error.
			}
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			log.Printf("Retrying GetLastServerAddress for account %d due to retryable error: %v", accountID, cbErr)
			return cbErr
		}

		resSlice := result.([]interface{})
		lastAddr = resSlice[0].(string)
		lastTime = resSlice[1].(time.Time)
		return nil
	}, config)

	return lastAddr, lastTime, err
}

// UpdateLastServerAddressWithRetry updates the last server address a user connected to, with retry logic.
func (rd *ResilientDatabase) UpdateLastServerAddressWithRetry(ctx context.Context, accountID int64, serverAddr string) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      3,
	}

	return retry.WithRetryAdvanced(ctx, func() error {
		// This is a write operation.
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().UpdateLastServerAddress(ctx, accountID, serverAddr)
		})

		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			log.Printf("Retrying UpdateLastServerAddress for account %d due to retryable error: %v", accountID, cbErr)
			return cbErr
		}

		return nil
	}, config)
}

func (rd *ResilientDatabase) Close() {
	if rd.failoverManager == nil {
		// This case is for when it's initialized without runtime failover.
		// The current code doesn't do this, but it's safe.
		return
	}
	// Stop the health checker
	close(rd.failoverManager.healthCheckStop)

	// Close all managed pools
	for _, pool := range rd.failoverManager.writePools {
		pool.database.Close()
	}

	// Close read pools only if they're different from write pools
	if rd.failoverManager.readPoolsAreDistinct() {
		for _, pool := range rd.failoverManager.readPools {
			pool.database.Close()
		}
	}
}

func (rd *ResilientDatabase) GetQueryBreakerState() circuitbreaker.State {
	return rd.queryBreaker.State()
}

func (rd *ResilientDatabase) GetWriteBreakerState() circuitbreaker.State {
	return rd.writeBreaker.State()
}

// --- AuthRateLimiter Wrappers ---

func (rd *ResilientDatabase) RecordAuthAttemptWithRetry(ctx context.Context, ipAddress, username, protocol string, success bool) error {
	// This is a high-frequency write operation. Retries should be short.
	config := retry.BackoffConfig{
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     500 * time.Millisecond,
		MaxRetries:      2,
	}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().RecordAuthAttempt(ctx, ipAddress, username, protocol, success)
		})
		if cbErr != nil && !rd.isRetryableError(cbErr) {
			return retry.Stop(cbErr)
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
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			ip, user, dbErr := rd.getOperationalDatabase().GetFailedAttemptsCountSeparateWindows(ctx, ipAddress, username, ipWindowDuration, usernameWindowDuration)
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
func (rd *ResilientDatabase) GetAuthAttemptsStats(ctx context.Context, windowDuration time.Duration) (map[string]interface{}, error) {
	return rd.getOperationalDatabase().GetAuthAttemptsStats(ctx, windowDuration)
}

func (rd *ResilientDatabase) CleanupOldAuthAttemptsWithRetry(ctx context.Context, maxAge time.Duration) (int64, error) {
	// This is a background cleanup task, low priority, no retries needed.
	config := retry.BackoffConfig{MaxRetries: 1}
	var count int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().CleanupOldAuthAttempts(ctx, maxAge)
		})
		if cbErr != nil {
			return retry.Stop(cbErr)
		}
		count = result.(int64)
		return nil
	}, config)
	return count, err
}

// --- Mailbox and Message Wrappers ---

func (rd *ResilientDatabase) GetMailboxByNameWithRetry(ctx context.Context, userID int64, name string) (*db.DBMailbox, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var mailbox *db.DBMailbox
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetMailboxByName(ctx, userID, name)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		mailbox = result.(*db.DBMailbox)
		return nil
	}, config)
	return mailbox, err
}

func (rd *ResilientDatabase) InsertMessageWithRetry(ctx context.Context, options *db.InsertMessageOptions, upload db.PendingUpload) (messageID int64, uid int64, err error) {
	config := retry.BackoffConfig{MaxRetries: 2} // Writes are less safe to retry automatically
	err = retry.WithRetry(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			messageID, uid, err = rd.getOperationalDatabase().InsertMessage(ctx, options, upload)
			return nil, err
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, config)
	return messageID, uid, err
}

func (rd *ResilientDatabase) GetMessagesByNumSetWithRetry(ctx context.Context, mailboxID int64, numSet imap.NumSet) ([]db.Message, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var messages []db.Message
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetMessagesByNumSet(ctx, mailboxID, numSet)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		messages = result.([]db.Message)
		return nil
	}, config)
	return messages, err
}

func (rd *ResilientDatabase) GetMailboxSummaryWithRetry(ctx context.Context, mailboxID int64) (*db.MailboxSummary, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var summary *db.MailboxSummary
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetMailboxSummary(ctx, mailboxID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		summary = result.(*db.MailboxSummary)
		return nil
	}, config)
	return summary, err
}

func (rd *ResilientDatabase) GetMailboxesWithRetry(ctx context.Context, userID int64, subscribed bool) ([]*db.DBMailbox, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var mailboxes []*db.DBMailbox
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetMailboxes(ctx, userID, subscribed)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		mailboxes = result.([]*db.DBMailbox)
		return nil
	}, config)
	return mailboxes, err
}

func (rd *ResilientDatabase) GetAccountIDByAddressWithRetry(ctx context.Context, address string) (int64, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var accountID int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetAccountIDByAddress(ctx, address)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		accountID = result.(int64)
		return nil
	}, config)
	return accountID, err
}

func (rd *ResilientDatabase) CreateDefaultMailboxesWithRetry(ctx context.Context, userID int64) error {
	config := retry.BackoffConfig{MaxRetries: 2}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().CreateDefaultMailboxes(ctx, userID)
		})
		if cbErr != nil && !rd.isRetryableError(cbErr) {
			return retry.Stop(cbErr)
		}
		return cbErr
	}, config)
}

func (rd *ResilientDatabase) PollMailboxWithRetry(ctx context.Context, mailboxID int64, sinceModSeq uint64) (*db.MailboxPoll, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var poll *db.MailboxPoll
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().PollMailbox(ctx, mailboxID, sinceModSeq)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		poll = result.(*db.MailboxPoll)
		return nil
	}, config)
	return poll, err
}

func (rd *ResilientDatabase) GetMessagesByFlagWithRetry(ctx context.Context, mailboxID int64, flag imap.Flag) ([]db.Message, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var messages []db.Message
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetMessagesByFlag(ctx, mailboxID, flag)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		messages = result.([]db.Message)
		return nil
	}, config)
	return messages, err
}

func (rd *ResilientDatabase) ExpungeMessageUIDsWithRetry(ctx context.Context, mailboxID int64, uids ...imap.UID) (int64, error) {
	config := retry.BackoffConfig{MaxRetries: 2}
	var modSeq int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().ExpungeMessageUIDs(ctx, mailboxID, uids...)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		modSeq = result.(int64)
		return nil
	}, config)
	return modSeq, err
}

func (rd *ResilientDatabase) GetPrimaryEmailForAccountWithRetry(ctx context.Context, accountID int64) (server.Address, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var address server.Address
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetPrimaryEmailForAccount(ctx, accountID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		address = result.(server.Address)
		return nil
	}, config)
	return address, err
}

// --- Connection Tracker Wrappers ---

func (rd *ResilientDatabase) RegisterConnectionWithRetry(ctx context.Context, accountID int64, protocol, clientAddr, serverAddr, instanceID string) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      3,
	}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().RegisterConnection(ctx, accountID, protocol, clientAddr, serverAddr, instanceID)
		})
		if cbErr != nil && !rd.isRetryableError(cbErr) {
			return retry.Stop(cbErr)
		}
		return cbErr
	}, config)
}

func (rd *ResilientDatabase) UpdateConnectionActivityWithRetry(ctx context.Context, accountID int64, protocol, clientAddr string) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     1 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
	}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().UpdateConnectionActivity(ctx, accountID, protocol, clientAddr)
		})
		if cbErr != nil && !rd.isRetryableError(cbErr) {
			return retry.Stop(cbErr)
		}
		return cbErr
	}, config)
}

func (rd *ResilientDatabase) UnregisterConnectionWithRetry(ctx context.Context, accountID int64, protocol, clientAddr string) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     1 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
	}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().UnregisterConnection(ctx, accountID, protocol, clientAddr)
		})
		if cbErr != nil && !rd.isRetryableError(cbErr) {
			return retry.Stop(cbErr)
		}
		return cbErr
	}, config)
}

func (rd *ResilientDatabase) CheckConnectionTerminationWithRetry(ctx context.Context, accountID int64, protocol, clientAddr string) (bool, error) {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     1 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
	}
	var shouldTerminate bool
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().CheckConnectionTermination(ctx, accountID, protocol, clientAddr)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		shouldTerminate = result.(bool)
		return nil
	}, config)
	return shouldTerminate, err
}

func (rd *ResilientDatabase) BatchRegisterConnectionsWithRetry(ctx context.Context, connections []db.ConnectionInfo) error {
	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     5 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
	}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().BatchRegisterConnections(ctx, connections)
		})
		if cbErr != nil && !rd.isRetryableError(cbErr) {
			return retry.Stop(cbErr)
		}
		return cbErr
	}, config)
}

func (rd *ResilientDatabase) BatchUpdateConnectionsWithRetry(ctx context.Context, connections []db.ConnectionInfo) error {
	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     5 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
	}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().BatchUpdateConnections(ctx, connections)
		})
		if cbErr != nil && !rd.isRetryableError(cbErr) {
			return retry.Stop(cbErr)
		}
		return cbErr
	}, config)
}

func (rd *ResilientDatabase) CleanupConnectionsByInstanceIDWithRetry(ctx context.Context, instanceID string) (int64, error) {
	config := retry.BackoffConfig{MaxRetries: 1} // No retries for cleanup
	var count int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().CleanupConnectionsByInstanceID(ctx, instanceID)
		})
		if cbErr != nil {
			return retry.Stop(cbErr)
		}
		count = result.(int64)
		return nil
	}, config)
	return count, err
}

func (rd *ResilientDatabase) GetTerminatedConnectionsByInstanceWithRetry(ctx context.Context, instanceID string) ([]db.ConnectionInfo, error) {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      3,
	}
	var connections []db.ConnectionInfo
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetTerminatedConnectionsByInstance(ctx, instanceID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		connections = result.([]db.ConnectionInfo)
		return nil
	}, config)
	return connections, err
}

// --- Sieve and Vacation Wrappers ---

func (rd *ResilientDatabase) GetActiveScriptWithRetry(ctx context.Context, userID int64) (*db.SieveScript, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var script *db.SieveScript
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetActiveScript(ctx, userID)
		})
		if cbErr != nil {
			if errors.Is(cbErr, consts.ErrDBNotFound) {
				return retry.Stop(cbErr)
			}
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		script = result.(*db.SieveScript)
		return nil
	}, config)
	return script, err
}

func (rd *ResilientDatabase) HasRecentVacationResponseWithRetry(ctx context.Context, userID int64, senderAddress string, duration time.Duration) (bool, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var hasRecent bool
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().HasRecentVacationResponse(ctx, userID, senderAddress, duration)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		hasRecent = result.(bool)
		return nil
	}, config)
	return hasRecent, err
}

func (rd *ResilientDatabase) RecordVacationResponseWithRetry(ctx context.Context, userID int64, senderAddress string) error {
	config := retry.BackoffConfig{MaxRetries: 2}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().RecordVacationResponse(ctx, userID, senderAddress)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, config)
}

// --- Mailbox Management Wrappers ---

func (rd *ResilientDatabase) InsertMessageCopyWithRetry(ctx context.Context, srcMessageUID imap.UID, srcMailboxID int64, destMailboxID int64, destMailboxName string) (imap.UID, error) {
	config := retry.BackoffConfig{MaxRetries: 2}
	var newUID imap.UID
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().InsertMessageCopy(ctx, srcMessageUID, srcMailboxID, destMailboxID, destMailboxName)
		})
		if cbErr != nil {
			if errors.Is(cbErr, consts.ErrDBUniqueViolation) {
				return retry.Stop(cbErr)
			}
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		newUID = result.(imap.UID)
		return nil
	}, config)
	return newUID, err
}

func (rd *ResilientDatabase) CreateMailboxWithRetry(ctx context.Context, userID int64, name string, parentID *int64) error {
	config := retry.BackoffConfig{MaxRetries: 2}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().CreateMailbox(ctx, userID, name, parentID)
		})
		if cbErr != nil {
			if errors.Is(cbErr, consts.ErrDBUniqueViolation) || errors.Is(cbErr, consts.ErrMailboxInvalidName) {
				return retry.Stop(cbErr)
			}
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, config)
}

func (rd *ResilientDatabase) DeleteMailboxWithRetry(ctx context.Context, mailboxID int64, userID int64) error {
	config := retry.BackoffConfig{MaxRetries: 2}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().DeleteMailbox(ctx, mailboxID, userID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, config)
}

func (rd *ResilientDatabase) RenameMailboxWithRetry(ctx context.Context, mailboxID int64, userID int64, newName string, newParentID *int64) error {
	config := retry.BackoffConfig{MaxRetries: 2}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().RenameMailbox(ctx, mailboxID, userID, newName, newParentID)
		})
		if cbErr != nil {
			if errors.Is(cbErr, consts.ErrMailboxAlreadyExists) || errors.Is(cbErr, consts.ErrMailboxInvalidName) {
				return retry.Stop(cbErr)
			}
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, config)
}

func (rd *ResilientDatabase) SetMailboxSubscribedWithRetry(ctx context.Context, mailboxID int64, userID int64, subscribed bool) error {
	config := retry.BackoffConfig{MaxRetries: 2}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().SetMailboxSubscribed(ctx, mailboxID, userID, subscribed)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, config)
}

func (rd *ResilientDatabase) CountMessagesGreaterThanUIDWithRetry(ctx context.Context, mailboxID int64, minUID imap.UID) (uint32, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var count uint32
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().CountMessagesGreaterThanUID(ctx, mailboxID, minUID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		count = result.(uint32)
		return nil
	}, config)
	return count, err
}

func (rd *ResilientDatabase) GetUniqueCustomFlagsForMailboxWithRetry(ctx context.Context, mailboxID int64) ([]string, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var flags []string
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetUniqueCustomFlagsForMailbox(ctx, mailboxID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		flags = result.([]string)
		return nil
	}, config)
	return flags, err
}

// --- Flag Management Wrappers ---

func (rd *ResilientDatabase) AddMessageFlagsWithRetry(ctx context.Context, messageUID imap.UID, mailboxID int64, newFlags []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	config := retry.BackoffConfig{MaxRetries: 2}
	err = retry.WithRetry(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			updatedFlags, modSeq, err = rd.getOperationalDatabase().AddMessageFlags(ctx, messageUID, mailboxID, newFlags)
			return nil, err
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, config)
	return
}

func (rd *ResilientDatabase) RemoveMessageFlagsWithRetry(ctx context.Context, messageUID imap.UID, mailboxID int64, flagsToRemove []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	config := retry.BackoffConfig{MaxRetries: 2}
	err = retry.WithRetry(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			updatedFlags, modSeq, err = rd.getOperationalDatabase().RemoveMessageFlags(ctx, messageUID, mailboxID, flagsToRemove)
			return nil, err
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, config)
	return
}

func (rd *ResilientDatabase) SetMessageFlagsWithRetry(ctx context.Context, messageUID imap.UID, mailboxID int64, newFlags []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	config := retry.BackoffConfig{MaxRetries: 2}
	err = retry.WithRetry(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			updatedFlags, modSeq, err = rd.getOperationalDatabase().SetMessageFlags(ctx, messageUID, mailboxID, newFlags)
			return nil, err
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, config)
	return
}

// --- Fetch Wrappers ---

func (rd *ResilientDatabase) GetMessageEnvelopeWithRetry(ctx context.Context, UID imap.UID, mailboxID int64) (*imap.Envelope, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var envelope *imap.Envelope
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetMessageEnvelope(ctx, UID, mailboxID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		envelope = result.(*imap.Envelope)
		return nil
	}, config)
	return envelope, err
}

func (rd *ResilientDatabase) GetMessageHeadersWithRetry(ctx context.Context, messageUID imap.UID, mailboxID int64) (string, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var headers string
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetMessageHeaders(ctx, messageUID, mailboxID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		headers = result.(string)
		return nil
	}, config)
	return headers, err
}

func (rd *ResilientDatabase) GetMessageTextBodyWithRetry(ctx context.Context, uid imap.UID, mailboxID int64) (string, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var body string
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetMessageTextBody(ctx, uid, mailboxID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		body = result.(string)
		return nil
	}, config)
	return body, err
}

func (rd *ResilientDatabase) GetMessagesSorted(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, sortCriteria []imap.SortCriterion) ([]db.Message, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var messages []db.Message
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetMessagesSorted(ctx, mailboxID, criteria, sortCriteria)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		messages = result.([]db.Message)
		return nil
	}, config)
	return messages, err
}

func (rd *ResilientDatabase) MoveMessagesWithRetry(ctx context.Context, ids *[]imap.UID, srcMailboxID, destMailboxID int64, userID int64) (map[imap.UID]imap.UID, error) {
	config := retry.BackoffConfig{MaxRetries: 2}
	var uidMap map[imap.UID]imap.UID
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().MoveMessages(ctx, ids, srcMailboxID, destMailboxID, userID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		uidMap = result.(map[imap.UID]imap.UID)
		return nil
	}, config)
	return uidMap, err
}

// --- Sieve Script Management Wrappers ---

func (rd *ResilientDatabase) GetUserScriptsWithRetry(ctx context.Context, userID int64) ([]*db.SieveScript, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var scripts []*db.SieveScript
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetUserScripts(ctx, userID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		scripts = result.([]*db.SieveScript)
		return nil
	}, config)
	return scripts, err
}

func (rd *ResilientDatabase) GetScriptByNameWithRetry(ctx context.Context, name string, userID int64) (*db.SieveScript, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var script *db.SieveScript
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetScriptByName(ctx, name, userID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		script = result.(*db.SieveScript)
		return nil
	}, config)
	return script, err
}

func (rd *ResilientDatabase) CreateScriptWithRetry(ctx context.Context, userID int64, name, script string) (*db.SieveScript, error) {
	config := retry.BackoffConfig{MaxRetries: 2}
	var createdScript *db.SieveScript
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().CreateScript(ctx, userID, name, script)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		createdScript = result.(*db.SieveScript)
		return nil
	}, config)
	return createdScript, err
}

func (rd *ResilientDatabase) UpdateScriptWithRetry(ctx context.Context, scriptID, userID int64, name, script string) (*db.SieveScript, error) {
	config := retry.BackoffConfig{MaxRetries: 2}
	var updatedScript *db.SieveScript
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().UpdateScript(ctx, scriptID, userID, name, script)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		updatedScript = result.(*db.SieveScript)
		return nil
	}, config)
	return updatedScript, err
}

func (rd *ResilientDatabase) DeleteScriptWithRetry(ctx context.Context, scriptID, userID int64) error {
	config := retry.BackoffConfig{MaxRetries: 2}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().DeleteScript(ctx, scriptID, userID)
		})
		if cbErr != nil && !rd.isRetryableError(cbErr) {
			return retry.Stop(cbErr)
		}
		return cbErr
	}, config)
}

func (rd *ResilientDatabase) SetScriptActiveWithRetry(ctx context.Context, scriptID, userID int64, active bool) error {
	config := retry.BackoffConfig{MaxRetries: 2}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().SetScriptActive(ctx, scriptID, userID, active)
		})
		if cbErr != nil && !rd.isRetryableError(cbErr) {
			return retry.Stop(cbErr)
		}
		return cbErr
	}, config)
}

// --- POP3 and Message List Wrappers ---

func (rd *ResilientDatabase) GetMailboxMessageCountAndSizeSumWithRetry(ctx context.Context, mailboxID int64) (int, int64, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var count int
	var sizeSum int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			c, s, err := rd.getOperationalDatabase().GetMailboxMessageCountAndSizeSum(ctx, mailboxID)
			if err != nil {
				return nil, err
			}
			return []interface{}{c, s}, nil
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		resSlice := result.([]interface{})
		count = resSlice[0].(int)
		sizeSum = resSlice[1].(int64)
		return nil
	}, config)
	return count, sizeSum, err
}

func (rd *ResilientDatabase) ListMessagesWithRetry(ctx context.Context, mailboxID int64) ([]db.Message, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var messages []db.Message
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().ListMessages(ctx, mailboxID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		messages = result.([]db.Message)
		return nil
	}, config)
	return messages, err
}

func (rd *ResilientDatabase) GetMessagesWithCriteriaWithRetry(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria) ([]db.Message, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var messages []db.Message
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetMessagesWithCriteria(ctx, mailboxID, criteria)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		messages = result.([]db.Message)
		return nil
	}, config)
	return messages, err
}

// --- Importer/Exporter Wrappers ---

var importExportRetryConfig = retry.BackoffConfig{
	InitialInterval: 500 * time.Millisecond,
	MaxInterval:     10 * time.Second,
	Multiplier:      2.0,
	Jitter:          true,
	MaxRetries:      3,
}

func (rd *ResilientDatabase) DeleteMessageByHashAndMailboxWithRetry(ctx context.Context, userID, mailboxID int64, hash string) (int64, error) {
	var count int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().DeleteMessageByHashAndMailbox(ctx, userID, mailboxID, hash)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		count = result.(int64)
		return nil
	}, importExportRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) CompleteS3UploadWithRetry(ctx context.Context, hash string, accountID int64) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().CompleteS3Upload(ctx, hash, accountID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, importExportRetryConfig)
}

// --- Cleanup Worker Wrappers ---

// cleanupRetryConfig provides a default retry strategy for background cleanup tasks.
var cleanupRetryConfig = retry.BackoffConfig{
	InitialInterval: 1 * time.Second,
	MaxInterval:     30 * time.Second,
	Multiplier:      2.0,
	Jitter:          true,
	MaxRetries:      3,
}

func (rd *ResilientDatabase) AcquireCleanupLockWithRetry(ctx context.Context) (bool, error) {
	var locked bool
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().AcquireCleanupLock(ctx)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		locked = result.(bool)
		return nil
	}, cleanupRetryConfig)
	return locked, err
}

func (rd *ResilientDatabase) ReleaseCleanupLockWithRetry(ctx context.Context) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			rd.getOperationalDatabase().ReleaseCleanupLock(ctx)
			return nil, nil
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, cleanupRetryConfig)
}

func (rd *ResilientDatabase) ExpungeOldMessagesWithRetry(ctx context.Context, maxAge time.Duration) (int64, error) {
	var count int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().ExpungeOldMessages(ctx, maxAge)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		count = result.(int64)
		return nil
	}, cleanupRetryConfig)
	return count, err
}

// --- HTTP API Wrappers ---

// apiRetryConfig provides a default retry strategy for HTTP API handlers.
var apiRetryConfig = retry.BackoffConfig{
	InitialInterval: 200 * time.Millisecond,
	MaxInterval:     2 * time.Second,
	Multiplier:      1.8,
	Jitter:          true,
	MaxRetries:      3,
}

func (rd *ResilientDatabase) AccountExistsWithRetry(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().AccountExists(ctx, email)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		exists = result.(bool)
		return nil
	}, apiRetryConfig)
	return exists, err
}

func (rd *ResilientDatabase) GetActiveConnectionsWithRetry(ctx context.Context) ([]db.ConnectionInfo, error) {
	var connections []db.ConnectionInfo
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetActiveConnections(ctx)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			connections = result.([]db.ConnectionInfo)
		}
		return nil
	}, apiRetryConfig)
	return connections, err
}

func (rd *ResilientDatabase) MarkConnectionsForTerminationWithRetry(ctx context.Context, criteria db.TerminationCriteria) (int64, error) {
	var count int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().MarkConnectionsForTermination(ctx, criteria)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		count = result.(int64)
		return nil
	}, apiRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) GetConnectionStatsWithRetry(ctx context.Context) (*db.ConnectionStats, error) {
	var stats *db.ConnectionStats
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetConnectionStats(ctx)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			stats = result.(*db.ConnectionStats)
		}
		return nil
	}, apiRetryConfig)
	return stats, err
}

func (rd *ResilientDatabase) GetUserConnectionsWithRetry(ctx context.Context, email string) ([]db.ConnectionInfo, error) {
	var connections []db.ConnectionInfo
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetUserConnections(ctx, email)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			connections = result.([]db.ConnectionInfo)
		}
		return nil
	}, apiRetryConfig)
	return connections, err
}

func (rd *ResilientDatabase) GetLatestCacheMetricsWithRetry(ctx context.Context) ([]*db.CacheMetricsRecord, error) {
	var metrics []*db.CacheMetricsRecord
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetLatestCacheMetrics(ctx)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			metrics = result.([]*db.CacheMetricsRecord)
		}
		return nil
	}, apiRetryConfig)
	return metrics, err
}

func (rd *ResilientDatabase) GetCacheMetricsWithRetry(ctx context.Context, instanceID string, since time.Time, limit int) ([]*db.CacheMetricsRecord, error) {
	var metrics []*db.CacheMetricsRecord
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetCacheMetrics(ctx, instanceID, since, limit)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			metrics = result.([]*db.CacheMetricsRecord)
		}
		return nil
	}, apiRetryConfig)
	return metrics, err
}

func (rd *ResilientDatabase) GetSystemHealthOverviewWithRetry(ctx context.Context, hostname string) (*db.SystemHealthOverview, error) {
	var overview *db.SystemHealthOverview
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetSystemHealthOverview(ctx, hostname)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			overview = result.(*db.SystemHealthOverview)
		}
		return nil
	}, apiRetryConfig)
	return overview, err
}

func (rd *ResilientDatabase) GetAllHealthStatusesWithRetry(ctx context.Context, hostname string) ([]*db.HealthStatus, error) {
	var statuses []*db.HealthStatus
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetAllHealthStatuses(ctx, hostname)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			statuses = result.([]*db.HealthStatus)
		}
		return nil
	}, apiRetryConfig)
	return statuses, err
}

func (rd *ResilientDatabase) GetHealthHistoryWithRetry(ctx context.Context, hostname, component string, since time.Time, limit int) ([]*db.HealthStatus, error) {
	var history []*db.HealthStatus
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetHealthHistory(ctx, hostname, component, since, limit)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			history = result.([]*db.HealthStatus)
		}
		return nil
	}, apiRetryConfig)
	return history, err
}

func (rd *ResilientDatabase) GetHealthStatusWithRetry(ctx context.Context, hostname, component string) (*db.HealthStatus, error) {
	var status *db.HealthStatus
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetHealthStatus(ctx, hostname, component)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			status = result.(*db.HealthStatus)
		}
		return nil
	}, apiRetryConfig)
	return status, err
}

func (rd *ResilientDatabase) GetUploaderStatsWithRetry(ctx context.Context, maxAttempts int) (*db.UploaderStats, error) {
	var stats *db.UploaderStats
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetUploaderStats(ctx, maxAttempts)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			stats = result.(*db.UploaderStats)
		}
		return nil
	}, apiRetryConfig)
	return stats, err
}

func (rd *ResilientDatabase) GetFailedUploadsWithRetry(ctx context.Context, maxAttempts, limit int) ([]db.PendingUpload, error) {
	var uploads []db.PendingUpload
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetFailedUploads(ctx, maxAttempts, limit)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			uploads = result.([]db.PendingUpload)
		}
		return nil
	}, apiRetryConfig)
	return uploads, err
}

func (rd *ResilientDatabase) GetAuthAttemptsStatsWithRetry(ctx context.Context, windowDuration time.Duration) (map[string]interface{}, error) {
	var stats map[string]interface{}
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetAuthAttemptsStats(ctx, windowDuration)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			stats = result.(map[string]interface{})
		}
		return nil
	}, apiRetryConfig)
	return stats, err
}

func (rd *ResilientDatabase) CleanupStaleConnectionsWithRetry(ctx context.Context, staleDuration time.Duration) (int64, error) {
	var count int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().CleanupStaleConnections(ctx, staleDuration)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		count = result.(int64)
		return nil
	}, adminRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) GetBlockedIPsWithRetry(ctx context.Context, ipWindow, usernameWindow time.Duration, maxAttemptsIP, maxAttemptsUsername int) ([]map[string]interface{}, error) {
	var blocked []map[string]interface{}
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetBlockedIPs(ctx, ipWindow, usernameWindow, maxAttemptsIP, maxAttemptsUsername)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			blocked = result.([]map[string]interface{})
		} else {
			blocked = nil
		}
		return nil
	}, adminRetryConfig)
	return blocked, err
}

// --- Admin Credentials Wrappers ---

func (rd *ResilientDatabase) AddCredentialWithRetry(ctx context.Context, req db.AddCredentialRequest) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().AddCredential(ctx, req)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, adminRetryConfig)
}

func (rd *ResilientDatabase) ListCredentialsWithRetry(ctx context.Context, email string) ([]db.Credential, error) {
	var credentials []db.Credential
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().ListCredentials(ctx, email)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			credentials = result.([]db.Credential)
		} else {
			credentials = nil
		}
		return nil
	}, adminRetryConfig)
	return credentials, err
}

func (rd *ResilientDatabase) DeleteCredentialWithRetry(ctx context.Context, email string) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().DeleteCredential(ctx, email)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, adminRetryConfig)
}

func (rd *ResilientDatabase) GetCredentialDetailsWithRetry(ctx context.Context, email string) (*db.CredentialDetails, error) {
	var details *db.CredentialDetails
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetCredentialDetails(ctx, email)
		})
		if cbErr != nil {
			if errors.Is(cbErr, consts.ErrUserNotFound) {
				return retry.Stop(cbErr)
			}
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			details = result.(*db.CredentialDetails)
		} else {
			details = nil
		}
		return nil
	}, adminRetryConfig)
	return details, err
}

// --- Admin Tool Wrappers ---

// adminRetryConfig provides a default retry strategy for short-lived admin CLI commands.
var adminRetryConfig = retry.BackoffConfig{
	InitialInterval: 250 * time.Millisecond,
	MaxInterval:     3 * time.Second,
	Multiplier:      1.8,
	Jitter:          true,
	MaxRetries:      3,
}

func (rd *ResilientDatabase) CreateAccountWithRetry(ctx context.Context, req db.CreateAccountRequest) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().CreateAccount(ctx, req)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, adminRetryConfig)
}

func (rd *ResilientDatabase) ListAccountsWithRetry(ctx context.Context) ([]*db.AccountSummary, error) {
	var accounts []*db.AccountSummary
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().ListAccounts(ctx)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			// Convert []AccountSummary to []*AccountSummary
			summaries := result.([]db.AccountSummary)
			accounts = make([]*db.AccountSummary, len(summaries))
			for i := range summaries {
				accounts[i] = &summaries[i]
			}
		} else {
			accounts = nil
		}
		return nil
	}, adminRetryConfig)
	return accounts, err
}

func (rd *ResilientDatabase) GetAccountDetailsWithRetry(ctx context.Context, email string) (*db.AccountDetails, error) {
	var details *db.AccountDetails
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetAccountDetails(ctx, email)
		})
		if cbErr != nil {
			if errors.Is(cbErr, consts.ErrUserNotFound) {
				return retry.Stop(cbErr)
			}
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			details = result.(*db.AccountDetails)
		} else {
			details = nil
		}
		return nil
	}, adminRetryConfig)
	return details, err
}

func (rd *ResilientDatabase) UpdateAccountWithRetry(ctx context.Context, req db.UpdateAccountRequest) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().UpdateAccount(ctx, req)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, adminRetryConfig)
}

func (rd *ResilientDatabase) DeleteAccountWithRetry(ctx context.Context, email string) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().DeleteAccount(ctx, email)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, adminRetryConfig)
}

func (rd *ResilientDatabase) RestoreAccountWithRetry(ctx context.Context, email string) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().RestoreAccount(ctx, email)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, adminRetryConfig)
}

func (rd *ResilientDatabase) CleanupFailedUploadsWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	var count int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().CleanupFailedUploads(ctx, gracePeriod)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		count = result.(int64)
		return nil
	}, cleanupRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) CleanupSoftDeletedAccountsWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	var count int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().CleanupSoftDeletedAccounts(ctx, gracePeriod)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		count = result.(int64)
		return nil
	}, cleanupRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) CleanupOldVacationResponsesWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	var count int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().CleanupOldVacationResponses(ctx, gracePeriod)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		count = result.(int64)
		return nil
	}, cleanupRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) CleanupOldHealthStatusesWithRetry(ctx context.Context, retention time.Duration) (int64, error) {
	var count int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().CleanupOldHealthStatuses(ctx, retention)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		count = result.(int64)
		return nil
	}, cleanupRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) GetUserScopedObjectsForCleanupWithRetry(ctx context.Context, gracePeriod time.Duration, batchSize int) ([]db.UserScopedObjectForCleanup, error) {
	var candidates []db.UserScopedObjectForCleanup
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetUserScopedObjectsForCleanup(ctx, gracePeriod, batchSize)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			candidates = result.([]db.UserScopedObjectForCleanup)
		} else {
			candidates = nil
		}
		return nil
	}, cleanupRetryConfig)
	return candidates, err
}

func (rd *ResilientDatabase) DeleteExpungedMessagesByS3KeyPartsWithRetry(ctx context.Context, accountID int64, s3Domain, s3Localpart, contentHash string) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().DeleteExpungedMessagesByS3KeyParts(ctx, accountID, s3Domain, s3Localpart, contentHash)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, cleanupRetryConfig)
}

func (rd *ResilientDatabase) CleanupOldMessageContentsWithRetry(ctx context.Context, ftsRetention time.Duration) (int64, error) {
	var count int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().CleanupOldMessageContents(ctx, ftsRetention)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		count = result.(int64)
		return nil
	}, cleanupRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) GetUnusedContentHashesWithRetry(ctx context.Context, batchSize int) ([]string, error) {
	var hashes []string
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetUnusedContentHashes(ctx, batchSize)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			hashes = result.([]string)
		} else {
			hashes = nil
		}
		return nil
	}, cleanupRetryConfig)
	return hashes, err
}

func (rd *ResilientDatabase) DeleteMessageContentByHashWithRetry(ctx context.Context, hash string) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().DeleteMessageContentByHash(ctx, hash)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, cleanupRetryConfig)
}

func (rd *ResilientDatabase) GetDanglingAccountsForFinalDeletionWithRetry(ctx context.Context, batchSize int) ([]int64, error) {
	var accounts []int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetDanglingAccountsForFinalDeletion(ctx, batchSize)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			accounts = result.([]int64)
		} else {
			accounts = nil
		}
		return nil
	}, cleanupRetryConfig)
	return accounts, err
}

func (rd *ResilientDatabase) FinalizeAccountDeletionWithRetry(ctx context.Context, accountID int64) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().FinalizeAccountDeletion(ctx, accountID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, cleanupRetryConfig)
}

// --- Cache Metrics Wrappers ---

func (rd *ResilientDatabase) StoreCacheMetricsWithRetry(ctx context.Context, instanceID, serverHostname string, hits, misses int64, uptimeSeconds int64) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
	}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().StoreCacheMetrics(ctx, instanceID, serverHostname, hits, misses, uptimeSeconds)
		})
		if cbErr != nil && !rd.isRetryableError(cbErr) {
			return retry.Stop(cbErr)
		}
		return cbErr
	}, config)
}

func (rd *ResilientDatabase) CleanupOldCacheMetricsWithRetry(ctx context.Context, olderThan time.Duration) (int64, error) {
	var count int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().CleanupOldCacheMetrics(ctx, olderThan)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		count = result.(int64)
		return nil
	}, cleanupRetryConfig)
	return count, err
}

// --- Cache Helper Wrappers ---

func (rd *ResilientDatabase) FindExistingContentHashesWithRetry(ctx context.Context, hashes []string) ([]string, error) {
	var existingHashes []string
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().FindExistingContentHashes(ctx, hashes)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			existingHashes = result.([]string)
		} else {
			existingHashes = nil
		}
		return nil
	}, cleanupRetryConfig) // Use cleanup config as this is for background maintenance
	return existingHashes, err
}

func (rd *ResilientDatabase) GetRecentMessagesForWarmupWithRetry(ctx context.Context, userID int64, mailboxNames []string, messageCount int) (map[string][]string, error) {
	var messages map[string][]string
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().GetRecentMessagesForWarmup(ctx, userID, mailboxNames, messageCount)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			messages = result.(map[string][]string)
		} else {
			messages = nil
		}
		return nil
	}, apiRetryConfig) // Use api config as this is for interactive performance
	return messages, err
}

// --- Health Status Wrappers ---

func (rd *ResilientDatabase) StoreHealthStatusWithRetry(ctx context.Context, hostname string, componentName string, status db.ComponentStatus, lastError error, checkCount, failCount int, metadata map[string]interface{}) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
	}
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().StoreHealthStatus(ctx, hostname, componentName, status, lastError, checkCount, failCount, metadata)
		})
		if cbErr != nil && !rd.isRetryableError(cbErr) {
			return retry.Stop(cbErr)
		}
		return cbErr
	}, config)
}

// --- Runtime Failover Implementation ---

// newRuntimeFailoverManager creates a new runtime failover manager with separate read/write pools
func newRuntimeFailoverManager(ctx context.Context, config *config.DatabaseConfig, runMigrations bool) (*RuntimeFailoverManager, error) {
	manager := &RuntimeFailoverManager{
		writePools:      make([]*DatabasePool, 0),
		readPools:       make([]*DatabasePool, 0),
		config:          config,
		healthCheckStop: make(chan struct{}),
	}

	// Create database pools for all write hosts
	if config.Write != nil && len(config.Write.Hosts) > 0 {
		for i, host := range config.Write.Hosts {
			pool, err := createDatabasePool(ctx, host, config.Write, config.LogQueries, "write", runMigrations)
			if err != nil {
				log.Printf("[RESILIENT-FAILOVER] Failed to create write pool for host %s: %v", host, err)
				continue
			}

			dbPool := &DatabasePool{
				database: pool,
				host:     host,
			}
			dbPool.isHealthy.Store(true) // Start as healthy

			manager.writePools = append(manager.writePools, dbPool)

			// First pool becomes the current one
			if i == 0 {
				manager.currentWriteIdx.Store(0)
			}
		}
	}

	// Create database pools for all read hosts
	if config.Read != nil && len(config.Read.Hosts) > 0 {
		for i, host := range config.Read.Hosts {
			pool, err := createDatabasePool(ctx, host, config.Read, config.LogQueries, "read", runMigrations)
			if err != nil {
				log.Printf("[RESILIENT-FAILOVER] Failed to create read pool for host %s: %v", host, err)
				continue
			}

			dbPool := &DatabasePool{
				database: pool,
				host:     host,
			}
			dbPool.isHealthy.Store(true) // Start as healthy

			manager.readPools = append(manager.readPools, dbPool)

			// First pool becomes the current one
			if i == 0 {
				manager.currentReadIdx.Store(0)
			}
		}
	}

	// Fallback: if no read pools, use write pools for reads
	if len(manager.readPools) == 0 && len(manager.writePools) > 0 {
		log.Printf("[RESILIENT-FAILOVER] No read pools configured, using write pools for read operations")
		manager.readPools = manager.writePools
		manager.currentReadIdx.Store(manager.currentWriteIdx.Load())
	}

	if len(manager.writePools) == 0 {
		return nil, fmt.Errorf("no healthy database pools available")
	}

	log.Printf("[RESILIENT-FAILOVER] Created runtime failover manager with %d write pools and %d read pools",
		len(manager.writePools), len(manager.readPools))
	return manager, nil
}

// createDatabasePool creates a single database connection pool
func createDatabasePool(ctx context.Context, host string, endpointConfig *config.DatabaseEndpointConfig, logQueries bool, poolType string, runMigrations bool) (*db.Database, error) {
	// Create a temporary config for this single host
	tempConfig := &config.DatabaseConfig{
		LogQueries: logQueries,
		Write: &config.DatabaseEndpointConfig{
			Hosts:           []string{host},
			Port:            endpointConfig.Port,
			User:            endpointConfig.User,
			Password:        endpointConfig.Password,
			Name:            endpointConfig.Name,
			TLSMode:         endpointConfig.TLSMode,
			MaxConns:        endpointConfig.MaxConns,
			MinConns:        endpointConfig.MinConns,
			MaxConnLifetime: endpointConfig.MaxConnLifetime,
			MaxConnIdleTime: endpointConfig.MaxConnIdleTime,
		},
	}

	database, err := db.NewDatabaseFromConfig(ctx, tempConfig, runMigrations)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s database pool for %s: %w", poolType, host, err)
	}

	return database, nil
}

// getCurrentDatabase returns the current active database pool
func (rd *ResilientDatabase) getCurrentDatabase() *db.Database {
	return rd.getCurrentDatabaseForOperation(true) // Default to write operation for backward compatibility
}

// getCurrentDatabaseForOperation returns the current active database pool for the specified operation type
func (rd *ResilientDatabase) getCurrentDatabaseForOperation(isWrite bool) *db.Database {
	if rd.failoverManager == nil {
		panic("failover manager not initialized")
	}

	rd.failoverManager.mu.RLock()
	defer rd.failoverManager.mu.RUnlock()

	if isWrite {
		if len(rd.failoverManager.writePools) == 0 {
			panic("no write database pools available")
		}

		currentIdx := rd.failoverManager.currentWriteIdx.Load()
		if currentIdx >= 0 && int(currentIdx) < len(rd.failoverManager.writePools) {
			return rd.failoverManager.writePools[currentIdx].database
		}

		// Fallback to first write pool
		return rd.failoverManager.writePools[0].database
	} else {
		if len(rd.failoverManager.readPools) == 0 {
			panic("no read database pools available")
		}

		currentIdx := rd.failoverManager.currentReadIdx.Load()
		if currentIdx >= 0 && int(currentIdx) < len(rd.failoverManager.readPools) {
			return rd.failoverManager.readPools[currentIdx].database
		}

		// Fallback to first read pool
		return rd.failoverManager.readPools[0].database
	}
}

// getOperationalDatabase returns the database to use for operations, with runtime failover
func (rd *ResilientDatabase) getOperationalDatabase() *db.Database {
	return rd.getOperationalDatabaseForOperation(true) // Default to write for backward compatibility
}

// getOperationalDatabaseForOperation returns the database to use for operations, with runtime failover
func (rd *ResilientDatabase) getOperationalDatabaseForOperation(isWrite bool) *db.Database {
	if rd.failoverManager == nil {
		panic("failover manager not initialized")
	}

	// Try to get a healthy database, with failover if needed
	return rd.getHealthyDatabaseWithFailover(isWrite)
}

// getHealthyDatabaseWithFailover attempts to get a healthy database, failing over if necessary
func (rd *ResilientDatabase) getHealthyDatabaseWithFailover(isWrite bool) *db.Database {
	var pools []*DatabasePool
	var currentIdx int64

	rd.failoverManager.mu.RLock()
	if isWrite {
		pools = rd.failoverManager.writePools
		currentIdx = rd.failoverManager.currentWriteIdx.Load()
	} else {
		pools = rd.failoverManager.readPools
		currentIdx = rd.failoverManager.currentReadIdx.Load()
	}
	rd.failoverManager.mu.RUnlock()

	if len(pools) == 0 {
		panic("no database pools available")
	}

	// --- Fast Path (Read Lock) ---
	// Check if the current pool is healthy. This is the most common case.
	rd.failoverManager.mu.RLock()
	currentPool := pools[currentIdx]
	isHealthy := currentPool.isHealthy.Load()
	rd.failoverManager.mu.RUnlock()

	if isHealthy {
		return currentPool.database
	}

	// --- Slow Path (Write Lock) ---
	// The current pool is unhealthy. Acquire a write lock to perform a failover.
	rd.failoverManager.mu.Lock()
	defer rd.failoverManager.mu.Unlock()

	// Double-check: Another goroutine might have already performed the failover while we were waiting for the lock.
	if isWrite {
		currentIdx = rd.failoverManager.currentWriteIdx.Load()
	} else {
		currentIdx = rd.failoverManager.currentReadIdx.Load()
	}

	if int(currentIdx) < len(pools) && pools[currentIdx].isHealthy.Load() {
		return pools[currentIdx].database
	}

	// Iterate through all pools to find a healthy one, starting from the next one.
	numPools := len(pools)
	for i := 1; i <= numPools; i++ {
		nextIdx := (int(currentIdx) + i) % numPools
		if pools[nextIdx].isHealthy.Load() {
			// Found a healthy pool, switch to it.
			if isWrite {
				rd.failoverManager.currentWriteIdx.Store(int64(nextIdx))
				log.Printf("[RESILIENT-FAILOVER] Switched write operations from unhealthy pool %s to healthy pool %s", pools[currentIdx].host, pools[nextIdx].host)
			} else {
				rd.failoverManager.currentReadIdx.Store(int64(nextIdx))
				log.Printf("[RESILIENT-FAILOVER] Switched read operations from unhealthy pool %s to healthy pool %s", pools[currentIdx].host, pools[nextIdx].host)
			}
			return pools[nextIdx].database
		}
	}

	// If we get here, no healthy pools were found. Return the current (unhealthy) pool as a last resort.
	opType := "read"
	if isWrite {
		opType = "write"
	}
	log.Printf("[RESILIENT-FAILOVER] WARNING: No healthy %s database pools available. Continuing to use unhealthy pool %s as a last resort.", opType, pools[currentIdx].host)
	return pools[currentIdx].database
}

// startRuntimeHealthChecking starts background health checking for all pools
func (rd *ResilientDatabase) startRuntimeHealthChecking(ctx context.Context) {
	if rd.failoverManager == nil {
		return
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	log.Printf("[RESILIENT-FAILOVER] Started background health checking")

	for {
		select {
		case <-ctx.Done():
			log.Printf("[RESILIENT-FAILOVER] Stopped background health checking")
			return
		case <-rd.failoverManager.healthCheckStop:
			log.Printf("[RESILIENT-FAILOVER] Stopped background health checking")
			return
		case <-ticker.C:
			rd.performHealthChecks(ctx)
		}
	}
}

// performHealthChecks checks the health of all database pools
func (rd *ResilientDatabase) performHealthChecks(ctx context.Context) {
	if rd.failoverManager == nil {
		return
	}

	// Check write pools
	for _, pool := range rd.failoverManager.writePools {
		go func(p *DatabasePool) {
			rd.checkPoolHealth(ctx, p, "write")
		}(pool)
	}

	// Check read pools (only if they're different from write pools)
	if rd.failoverManager.readPoolsAreDistinct() {
		for _, pool := range rd.failoverManager.readPools {
			go func(p *DatabasePool) {
				rd.checkPoolHealth(ctx, p, "read")
			}(pool)
		}
	}
}

// checkPoolHealth checks the health of a single pool
func (rd *ResilientDatabase) checkPoolHealth(ctx context.Context, pool *DatabasePool, poolType string) {
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := pool.database.WritePool.Ping(healthCtx)
	wasHealthy := pool.isHealthy.Load()
	isHealthyNow := (err == nil)

	if wasHealthy != isHealthyNow {
		pool.isHealthy.Store(isHealthyNow)
		if isHealthyNow {
			log.Printf("[RESILIENT-FAILOVER] %s database pool recovered: %s", poolType, pool.host)
		} else {
			log.Printf("[RESILIENT-FAILOVER] %s database pool failed health check: %s (error: %v)", poolType, pool.host, err)
			pool.lastFailure.Store(time.Now().Unix())
			pool.failCount.Add(1)
		}
	}
}

// StartPoolMetrics starts a goroutine that periodically collects connection pool metrics
// from all managed database pools (both read and write) and exposes them via Prometheus
func (rd *ResilientDatabase) StartPoolMetrics(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rd.collectAggregatedPoolStats()
			}
		}
	}()
}

// collectAggregatedPoolStats gathers stats from all write and read pools and updates metrics
func (rd *ResilientDatabase) collectAggregatedPoolStats() {
	rd.failoverManager.mu.RLock()
	defer rd.failoverManager.mu.RUnlock()

	// Import metrics package for accessing the metrics
	// Note: This assumes the metrics package is imported at the top of the file

	// Collect stats from all write pools
	var totalWriteConns, idleWriteConns, inUseWriteConns int32
	for _, pool := range rd.failoverManager.writePools {
		if pool.database != nil && pool.database.WritePool != nil {
			stats := pool.database.WritePool.Stat()
			totalWriteConns += stats.TotalConns()
			idleWriteConns += stats.IdleConns()
			inUseWriteConns += stats.AcquiredConns()
		}
	}

	// Update aggregated write pool metrics
	if len(rd.failoverManager.writePools) > 0 {
		metrics.DBPoolTotalConns.WithLabelValues("write").Set(float64(totalWriteConns))
		metrics.DBPoolIdleConns.WithLabelValues("write").Set(float64(idleWriteConns))
		metrics.DBPoolInUseConns.WithLabelValues("write").Set(float64(inUseWriteConns))
	}

	// Collect stats from read pools only if they are distinct from write pools
	if rd.failoverManager.readPoolsAreDistinct() {
		var totalReadConns, idleReadConns, inUseReadConns int32
		for _, pool := range rd.failoverManager.readPools {
			if pool.database != nil && pool.database.ReadPool != nil {
				stats := pool.database.ReadPool.Stat()
				totalReadConns += stats.TotalConns()
				idleReadConns += stats.IdleConns()
				inUseReadConns += stats.AcquiredConns()
			}
		}

		// Update aggregated read pool metrics
		metrics.DBPoolTotalConns.WithLabelValues("read").Set(float64(totalReadConns))
		metrics.DBPoolIdleConns.WithLabelValues("read").Set(float64(idleReadConns))
		metrics.DBPoolInUseConns.WithLabelValues("read").Set(float64(inUseReadConns))
	} else {
		// If read pools are not distinct, ensure their metrics are zeroed out
		// to avoid reporting stale or incorrect data.
		metrics.DBPoolTotalConns.WithLabelValues("read").Set(0)
		metrics.DBPoolIdleConns.WithLabelValues("read").Set(0)
		metrics.DBPoolInUseConns.WithLabelValues("read").Set(0)
	}
}

// StartPoolHealthMonitoring starts background monitoring of connection pool health
// for all managed database pools with enhanced metrics collection
func (rd *ResilientDatabase) StartPoolHealthMonitoring(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second) // Align with existing health check interval
		defer ticker.Stop()

		log.Printf("[RESILIENT-FAILOVER] Starting aggregated pool health monitoring every 30s")

		for {
			select {
			case <-ctx.Done():
				log.Printf("[RESILIENT-FAILOVER] Stopping aggregated pool health monitoring")
				return
			case <-ticker.C:
				rd.monitorAggregatedPoolHealth()
			}
		}
	}()
}

// monitorAggregatedPoolHealth performs periodic health checks and updates metrics for all pools
func (rd *ResilientDatabase) monitorAggregatedPoolHealth() {
	rd.failoverManager.mu.RLock()
	defer rd.failoverManager.mu.RUnlock()

	// Monitor write pools
	rd.monitorPoolGroup(rd.failoverManager.writePools, "write")

	// Monitor read pools only if they are distinct
	if rd.failoverManager.readPoolsAreDistinct() {
		rd.monitorPoolGroup(rd.failoverManager.readPools, "read")
	}
}

// monitorPoolGroup monitors a group of database pools (write or read)
func (rd *ResilientDatabase) monitorPoolGroup(pools []*DatabasePool, poolType string) {
	var (
		totalConns      int32
		idleConns       int32
		acquiredConns   int32
		maxConns        int32
		exhaustionCount int
	)

	for _, pool := range pools {
		if pool.database == nil {
			continue
		}

		var poolToCheck *pgxpool.Pool
		if poolType == "write" && pool.database.WritePool != nil {
			poolToCheck = pool.database.WritePool
		} else if poolType == "read" && pool.database.ReadPool != nil {
			poolToCheck = pool.database.ReadPool
		}

		if poolToCheck != nil {
			stats := poolToCheck.Stat()
			totalConns += stats.TotalConns()
			idleConns += stats.IdleConns()
			acquiredConns += stats.AcquiredConns()
			maxConns += stats.MaxConns()

			// Check for pool exhaustion (>95% utilization)
			if stats.MaxConns() > 0 {
				utilization := float64(stats.AcquiredConns()) / float64(stats.MaxConns())
				if utilization > 0.95 {
					exhaustionCount++
					log.Printf("[RESILIENT-FAILOVER] WARNING: %s pool %s near exhaustion (%.1f%% utilization)",
						poolType, pool.host, utilization*100)
				}
			}

			// Check for slow connection acquisition
			// Note: pgxpool.Stat() doesn't provide acquisition duration directly
			// This would need to be tracked separately or estimated
		}
	}

	// Update aggregated metrics
	metrics.DBPoolTotalConns.WithLabelValues(poolType).Set(float64(totalConns))
	metrics.DBPoolIdleConns.WithLabelValues(poolType).Set(float64(idleConns))
	metrics.DBPoolInUseConns.WithLabelValues(poolType).Set(float64(acquiredConns))

	if exhaustionCount > 0 {
		metrics.DBPoolExhaustion.WithLabelValues(poolType).Add(float64(exhaustionCount))
	}

	log.Printf("[RESILIENT-FAILOVER] %s pools health: %d total conns, %d idle, %d in-use across %d pools",
		poolType, totalConns, idleConns, acquiredConns, len(pools))
}

// --- Uploader Worker Wrappers ---

func (rd *ResilientDatabase) AcquireAndLeasePendingUploadsWithRetry(ctx context.Context, instanceId string, limit int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error) {
	var uploads []db.PendingUpload
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().AcquireAndLeasePendingUploads(ctx, instanceId, limit, retryInterval, maxAttempts)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			uploads = result.([]db.PendingUpload)
		} else {
			uploads = nil
		}
		return nil
	}, cleanupRetryConfig)
	return uploads, err
}

func (rd *ResilientDatabase) MarkUploadAttemptWithRetry(ctx context.Context, contentHash string, accountID int64) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabase().MarkUploadAttempt(ctx, contentHash, accountID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		return nil
	}, cleanupRetryConfig)
}

func (rd *ResilientDatabase) IsContentHashUploadedWithRetry(ctx context.Context, contentHash string, accountID int64) (bool, error) {
	var isUploaded bool
	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabase().IsContentHashUploaded(ctx, contentHash, accountID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		isUploaded = result.(bool)
		return nil
	}, cleanupRetryConfig)
	return isUploaded, err
}
