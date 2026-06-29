package imap

import (
	"context"
	"errors"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/retry"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/storage"
)

// isTransientError performs a comprehensive check for transient infrastructure errors.
// It checks for:
//   - TransientError wrapper (via server.IsTransientError)
//   - Circuit breaker errors (open/too many requests)
//   - Database connection pool and connection errors
//   - Storage retrieval failures
//   - Retry exhaustion
//   - Context timeouts and cancellations
//
// This function lives in server/imap (rather than server/) to avoid import cycles,
// since the server package cannot import db.
func isTransientError(err error) bool {
	if err == nil {
		return false
	}

	// Check for explicit TransientError wrapper
	if server.IsTransientError(err) {
		return true
	}

	// Circuit breaker
	if errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) ||
		errors.Is(err, circuitbreaker.ErrTooManyRequests) {
		return true
	}

	// Database connection pool / connection errors
	if errors.Is(err, db.ErrNoConnections) ||
		errors.Is(err, db.ErrConnectionRefused) ||
		errors.Is(err, db.ErrTooManyClients) ||
		errors.Is(err, db.ErrMaxClientConn) ||
		errors.Is(err, db.ErrFailedToConnect) {
		return true
	}

	// Row-lock wait timeout (lock_timeout fired): transient contention, the client
	// should back off and retry rather than see a [SERVERBUG].
	if errors.Is(err, db.ErrDBLockTimeout) {
		return true
	}

	// Storage retrieval errors
	if errors.Is(err, storage.ErrRetrieveFailed) ||
		errors.Is(err, storage.ErrEmptyData) {
		return true
	}

	// Retry exhaustion
	if errors.Is(err, retry.ErrMaxRetriesExceeded) {
		return true
	}

	// Context errors
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) {
		return true
	}

	return false
}
