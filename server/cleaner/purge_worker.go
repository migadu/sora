package cleaner

// purge_worker.go - performs the account purges that were requested elsewhere.
//
// A purge is requested on any node: the Admin API (a proxy with no object storage
// included) soft-deletes the account, ends its sessions and marks it, see
// db.RequestAccountPurge. This worker runs on every node that has object storage, polls
// for marked accounts, claims each with an advisory lock so that only one node works on
// it, and runs PurgeAccount. A purge that fails is backed off per account, so a broken
// account is not retried every poll by every node, and is tried again later; a new
// request from the operator clears the backoff.
//
// What makes a request certain to be picked up is not this worker but what it rests on:
// the mark is a column that survives restarts and is cleared only by the purge finishing
// or by a restore; every backend node polls; a node that dies mid-purge loses its lock
// and another resumes (the purge is resumable, and safe to run twice); and the pending
// count and oldest age are gauges, so a stall is something to alert on. Even with no
// worker running at all, a marked account is soft-deleted, and the cleaner removes it
// after the grace period as it would any deleted account.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"
)

const (
	// purgeWorkerBatch is how many due accounts one cycle takes on. Each is purged to the
	// end before the next, so a cycle can run long; the poll is skipped while one runs.
	purgeWorkerBatch = 10
	// purgeWorkerMinInterval floors the poll interval.
	purgeWorkerMinInterval = 5 * time.Second
	// purgeBackoffBase and purgeBackoffMax bound the per-account backoff after a failed
	// attempt: base, doubled per attempt, capped at max.
	purgeBackoffBase = time.Minute
	purgeBackoffMax  = time.Hour
)

// PurgeWorkerDatabase is what the purge worker needs from the database.
type PurgeWorkerDatabase interface {
	AccountPurgeDatabase
	ListAccountsForPurgeWithRetry(ctx context.Context, limit int) ([]int64, error)
	ExecuteWithAccountPurgeLock(ctx context.Context, accountID int64, fn func(ctx context.Context) error) (bool, error)
	RecordAccountPurgeFailureWithRetry(ctx context.Context, accountID int64, base, max time.Duration) (time.Time, error)
	PendingAccountPurgesWithRetry(ctx context.Context) (int64, time.Duration, error)
}

// PurgeWorker performs requested account purges on a node with object storage.
type PurgeWorker struct {
	rdb      PurgeWorkerDatabase
	s3       S3BulkDeleter
	interval time.Duration
	wake     chan struct{}
	stopCh   chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
	running  bool
}

// NewPurgeWorker creates a purge worker that polls every interval. S3 deletes go through
// the same resilient wrapper (retries, circuit breaker) the cleaner uses.
func NewPurgeWorker(rdb *resilient.ResilientDatabase, s3 *storage.S3Storage, interval time.Duration) *PurgeWorker {
	return newPurgeWorker(rdb, resilient.NewResilientS3Storage(s3), interval)
}

func newPurgeWorker(rdb PurgeWorkerDatabase, s3 S3BulkDeleter, interval time.Duration) *PurgeWorker {
	return &PurgeWorker{
		rdb:      rdb,
		s3:       s3,
		interval: interval,
		wake:     make(chan struct{}, 1),
		stopCh:   make(chan struct{}),
	}
}

// Start runs the worker in the background until ctx is done or Stop is called.
func (w *PurgeWorker) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = true
	w.mu.Unlock()

	w.wg.Add(1)
	go w.run(ctx)
	logger.Info("Purge: worker started", "poll_interval", w.interval)
	return nil
}

// Stop stops the worker and waits for a running cycle to end. Safe to call twice.
func (w *PurgeWorker) Stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	w.running = false
	w.mu.Unlock()

	close(w.stopCh)
	w.wg.Wait()
	logger.Info("Purge: worker stopped")
}

// Wake asks the worker to poll now rather than at the next tick: the Admin API calls it
// after marking an account on a node that runs a worker, so a purge requested on a
// backend starts at once. Never blocks; a wake while one is pending is folded into it.
func (w *PurgeWorker) Wake() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *PurgeWorker) run(ctx context.Context) {
	defer func() {
		w.mu.Lock()
		w.running = false
		w.mu.Unlock()
		w.wg.Done()
	}()

	interval := w.interval
	if interval < purgeWorkerMinInterval {
		logger.Warn("Purge: configured poll interval below minimum, using minimum", "interval", interval, "minimum", purgeWorkerMinInterval)
		interval = purgeWorkerMinInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	cycle := func() {
		if _, err := w.RunOnce(ctx); err != nil && ctx.Err() == nil {
			logger.Error("Purge: cycle failed", "error", err)
		}
	}
	cycle()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case <-ticker.C:
			cycle()
		case <-w.wake:
			cycle()
		}
	}
}

// RunOnce runs one cycle: it refreshes the pending-purge gauges, lists the accounts whose
// purge is due, and purges each it can claim. It returns how many accounts are gone. A
// purge that fails is logged, counted and backed off; it does not stop the cycle. The
// error is for a cycle that could not run at all (the list failed) or was cancelled.
func (w *PurgeWorker) RunOnce(ctx context.Context) (int, error) {
	w.reportPending(ctx)

	accountIDs, err := w.rdb.ListAccountsForPurgeWithRetry(ctx, purgeWorkerBatch)
	if err != nil {
		return 0, fmt.Errorf("failed to list accounts for purge: %w", err)
	}

	purged := 0
	for _, accountID := range accountIDs {
		if ctx.Err() != nil {
			return purged, ctx.Err()
		}

		var stats PurgeStats
		claimed, err := w.rdb.ExecuteWithAccountPurgeLock(ctx, accountID, func(ctx context.Context) error {
			var purgeErr error
			stats, purgeErr = PurgeAccount(ctx, w.rdb, w.s3, accountID)
			return purgeErr
		})
		switch {
		case err == nil && !claimed:
			logger.Info("Purge: account is being purged by another node, skipping", "account_id", accountID)
			continue
		case errors.Is(err, ErrAccountInService):
			// Restored between the poll and the claim; the restore cleared its mark.
			logger.Info("Purge: account was restored, not purged", "account_id", accountID)
			continue
		case err != nil:
			if ctx.Err() != nil {
				// Shutting down, not a failure of this account: no backoff.
				return purged, ctx.Err()
			}
			metrics.AccountPurgesTotal.WithLabelValues("failure").Inc()
			next, recordErr := w.rdb.RecordAccountPurgeFailureWithRetry(ctx, accountID, purgeBackoffBase, purgeBackoffMax)
			if recordErr != nil {
				logger.Error("Purge: failed to record a failed purge attempt", "account_id", accountID, "error", recordErr)
			}
			logger.Warn("Purge: account purge failed; it stays out of service and is retried later",
				"account_id", accountID, "next_attempt", next,
				"s3_objects_deleted", stats.S3Objects, "messages_deleted", stats.Messages, "error", err)
			continue
		}

		purged++
		metrics.AccountPurgesTotal.WithLabelValues("success").Inc()
		logger.Info("Purge: account purged", "account_id", accountID,
			"s3_objects_deleted", stats.S3Objects, "messages_deleted", stats.Messages)
	}

	if purged > 0 {
		w.reportPending(ctx)
	}
	return purged, nil
}

// reportPending refreshes the pending-purge gauges. A failure to read them is logged;
// the cycle goes on.
func (w *PurgeWorker) reportPending(ctx context.Context) {
	count, oldest, err := w.rdb.PendingAccountPurgesWithRetry(ctx)
	if err != nil {
		if ctx.Err() == nil {
			logger.Warn("Purge: failed to count pending purges", "error", err)
		}
		return
	}
	metrics.AccountPurgesPending.Set(float64(count))
	metrics.AccountPurgeOldestPendingSeconds.Set(oldest.Seconds())
}

var _ PurgeWorkerDatabase = (*resilient.ResilientDatabase)(nil)
