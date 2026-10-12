package cleaner

// purge.go - immediate, irreversible deletion of one account, for the Admin API
// (`DELETE /admin/accounts/{email}?purge=true`) and sora-admin (`accounts delete --purge`,
// `accounts purge-domain`).
//
// A purge is the cleaner's own pipeline for soft-deleted accounts, run for one account
// now instead of after the grace period: the bounded hard delete of its mailboxes and
// messages, the S3 phase under the uploader's per-object locks, the FTS drain, and the
// finalize that deletes the credentials and the account row together in one transaction.
// Sharing it is the point: the purge inherits every fix those steps received, and there is
// no second copy of the deletion order to keep in step.
//
// What a failed purge leaves behind is a soft-deleted account that still has its
// credentials. Running the purge again resumes it, and if nobody does, the cleaner
// finishes the account once its grace period has passed.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
)

// ErrAccountInService is returned by PurgeAccount for an account that is not
// soft-deleted: it was restored while the purge ran, or never taken out of service.
var ErrAccountInService = errors.New("account is in service: it was restored, or never taken out of service")

const (
	// purgeMaxPasses bounds how often a purge runs the whole pipeline again when the
	// account still holds rows at the end of a pass: a body whose upload is in flight
	// holds its lock, S3 refused a delete, or a delivery that passed its recipient check
	// just before the account went out of service landed afterwards.
	purgeMaxPasses = 5
	// purgeRetryDelay is the pause before the second pass, doubled before each further one.
	purgeRetryDelay = 250 * time.Millisecond
	// purgeObjectBatch is how many keys one round of the S3 phase lists.
	purgeObjectBatch = db.BATCH_PURGE_SIZE
	// purgeGracePeriod is the grace the orphan re-check applies. The cleaner keeps
	// recently expunged bodies for a while; a purge keeps none. It is negative rather
	// than zero because the re-check compares the rows' expunged_at, stamped by the
	// database clock, with this node's clock: zero would take a node running behind the
	// database for "just expunged" and skip every body the purge itself expunged. Live
	// rows are still excluded, whatever this is.
	purgeGracePeriod = -24 * time.Hour
)

// AccountDisabler is what DisableAccount needs from the database.
type AccountDisabler interface {
	GetAccountIDByEmailWithRetry(ctx context.Context, email string) (int64, error)
	DeleteAccountWithRetry(ctx context.Context, email string) error
}

// AccountPurgeDatabase is what PurgeAccount needs from the database.
type AccountPurgeDatabase interface {
	s3ObjectReaper
	HardDeleteAccountWithRetry(ctx context.Context, accountID int64) error
	GetPurgeableObjectsForAccountWithRetry(ctx context.Context, accountID int64, limit int) ([]db.UserScopedObjectForCleanup, error)
	DeleteFTSRowsForAccountWithRetry(ctx context.Context, accountID int64, limit int) (int64, error)
	FinalizeAccountDeletionsWithRetry(ctx context.Context, accountIDs []int64) (int64, error)
	GetAccountDeletionStateWithRetry(ctx context.Context, accountID int64) (exists, softDeleted bool, err error)
}

// PurgeStats is what a purge removed, so far if it failed.
type PurgeStats struct {
	S3Objects int   // S3 keys deleted, including keys of bodies that never reached S3
	Messages  int64 // message rows deleted
}

// DisableAccount takes the account behind email out of service by soft-deleting it, so it
// can no longer sign in or be delivered to, and returns its id. An account that is
// already soft-deleted is fine. An unknown address returns consts.ErrUserNotFound.
//
// It does not end the account's open sessions; a caller that can reach them (the Admin
// API, through its connection trackers) does that next.
func DisableAccount(ctx context.Context, rdb AccountDisabler, email string) (int64, error) {
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, email)
	if err != nil {
		return 0, err
	}
	if err := rdb.DeleteAccountWithRetry(ctx, email); err != nil && !errors.Is(err, db.ErrAccountAlreadyDeleted) {
		return 0, fmt.Errorf("failed to take account out of service: %w", err)
	}
	return accountID, nil
}

// PurgeAccount permanently deletes a soft-deleted account and everything it holds: its
// mailboxes and messages, their S3 bodies, its search vectors, its credentials and the
// account row. Call DisableAccount first.
//
// Each pass runs the whole pipeline; a pass that cannot finalize the account (something
// is still there) is followed by another after a pause, up to purgeMaxPasses. Every
// failure leaves the account soft-deleted with its credentials, so it can be run again.
// It never deletes the body of a live message.
func PurgeAccount(ctx context.Context, rdb AccountPurgeDatabase, s3 S3BulkDeleter, accountID int64) (PurgeStats, error) {
	// Every read sees the deletes this purge just made.
	ctx = context.WithValue(ctx, consts.UseMasterDBKey, true)

	var stats PurgeStats
	delay := purgeRetryDelay
	for pass := 1; ; pass++ {
		if err := rdb.HardDeleteAccountWithRetry(ctx, accountID); err != nil {
			return stats, fmt.Errorf("failed to remove the account's mailboxes: %w", err)
		}
		if err := purgeAccountObjects(ctx, rdb, s3, accountID, &stats); err != nil {
			return stats, err
		}
		if _, err := drainAccountFTS(ctx, rdb, accountID); err != nil {
			return stats, fmt.Errorf("failed to remove the account's search index: %w", err)
		}
		finalized, err := rdb.FinalizeAccountDeletionsWithRetry(ctx, []int64{accountID})
		if err != nil {
			return stats, fmt.Errorf("failed to remove the account: %w", err)
		}
		if finalized == 1 {
			return stats, nil
		}

		exists, softDeleted, err := rdb.GetAccountDeletionStateWithRetry(ctx, accountID)
		if err != nil {
			return stats, fmt.Errorf("failed to read the account's state: %w", err)
		}
		if !exists {
			return stats, nil // a concurrent purge, or the cleaner, finished it
		}
		if !softDeleted {
			return stats, ErrAccountInService
		}
		if pass == purgeMaxPasses {
			return stats, fmt.Errorf("account still holds data after %d passes (an upload in flight, S3 refusing deletes, or mail still arriving); it stays out of service, and running the purge again, or the cleaner after its grace period, finishes it", pass)
		}
		logger.Info("Purge: account still holds data, running another pass", "account_id", accountID, "pass", pass, "delay", delay)
		select {
		case <-ctx.Done():
			return stats, ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// purgeAccountObjects deletes the S3 keys of the account's expunged rows and the rows,
// until none are left or a round makes no progress. Each round that goes on has deleted
// rows, and only rows this purge already expunged are listed, so it cannot spin; what a
// round could not delete (a body whose upload holds its lock, a key S3 refused) is left
// for the next pass.
func purgeAccountObjects(ctx context.Context, rdb AccountPurgeDatabase, s3 S3BulkDeleter, accountID int64, stats *PurgeStats) error {
	for {
		candidates, err := rdb.GetPurgeableObjectsForAccountWithRetry(ctx, accountID, purgeObjectBatch)
		if err != nil {
			return fmt.Errorf("failed to list the account's S3 objects: %w", err)
		}
		if len(candidates) == 0 {
			return nil
		}
		objects, rows, err := reapS3Objects(ctx, rdb, s3, purgeGracePeriod, candidates)
		stats.S3Objects += objects
		stats.Messages += rows
		if err != nil {
			return fmt.Errorf("failed to delete the account's S3 objects: %w", err)
		}
		if rows == 0 {
			return nil
		}
	}
}

// ftsDrainer is the database side of drainAccountFTS.
type ftsDrainer interface {
	DeleteFTSRowsForAccountWithRetry(ctx context.Context, accountID int64, limit int) (int64, error)
}

// drainAccountFTS deletes the account's search vectors in bounded batches, so that the
// finalize, which deletes them too as a safety net, finds none: an account has one row
// per distinct body, and one unbounded DELETE in the finalize transaction could be
// millions of rows.
func drainAccountFTS(ctx context.Context, rdb ftsDrainer, accountID int64) (int64, error) {
	var total int64
	for {
		deleted, err := rdb.DeleteFTSRowsForAccountWithRetry(ctx, accountID, db.BATCH_PURGE_SIZE)
		if err != nil {
			return total, err
		}
		total += deleted
		if deleted == 0 || ctx.Err() != nil {
			return total, ctx.Err()
		}
	}
}

// The production types satisfy the purge's interfaces.
var (
	_ AccountPurgeDatabase = (*resilient.ResilientDatabase)(nil)
	_ AccountDisabler      = (*resilient.ResilientDatabase)(nil)
	_ S3BulkDeleter        = (*resilient.ResilientS3Storage)(nil)
)
