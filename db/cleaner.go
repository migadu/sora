package db

import (
	"context"
	"fmt"
	"hash/fnv"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/logger"
)

const BATCH_PURGE_SIZE = 1000

// Advisory lock ID for cleanup worker coordination
// Computed as: hash("sora_cleanup_worker") & 0x7FFFFFFF to ensure positive int32
const CLEANUP_ADVISORY_LOCK_ID = 1876543210

// UserScopedObjectForCleanup represents a user-specific object that is a candidate for cleanup.
type UserScopedObjectForCleanup struct {
	AccountID   int64
	ContentHash string
	S3Domain    string
	S3Localpart string
}

// AcquireCleanupLock attempts to acquire a transaction-scoped advisory lock for the cleanup worker.
// Returns true if lock was acquired, false if another instance holds it.
// The lock is automatically released when the transaction commits or rolls back.
// NOTE: Uses transaction-scoped lock (pg_advisory_xact_lock) to avoid connection pool issues.
func (d *Database) AcquireCleanupLock(ctx context.Context, tx pgx.Tx) (bool, error) {
	var acquired bool
	err := tx.QueryRow(ctx,
		"SELECT pg_try_advisory_xact_lock($1)",
		CLEANUP_ADVISORY_LOCK_ID).Scan(&acquired)
	if err != nil {
		return false, fmt.Errorf("failed to acquire cleanup advisory lock: %w", err)
	}
	return acquired, nil
}

// ReleaseCleanupLock is a no-op for transaction-scoped advisory locks.
// The lock is automatically released when the transaction commits or rolls back.
// Kept for API compatibility.
func (d *Database) ReleaseCleanupLock(ctx context.Context, tx pgx.Tx) error {
	// Transaction-scoped locks (pg_advisory_xact_lock) are automatically released
	// on COMMIT or ROLLBACK, so we don't need to explicitly unlock.
	return nil
}

// GetS3ObjectLockID generates a stable int64 lock ID for a given object pair.
// Uses FNV-1a to ensure consistency across nodes.
func GetS3ObjectLockID(accountID int64, contentHash string) int64 {
	h := fnv.New64a()
	h.Write([]byte(fmt.Sprintf("%d:%s", accountID, contentHash)))
	return int64(h.Sum64())
}

// AcquireS3ObjectLock attempts to acquire a transaction-scoped advisory lock for a specific S3 object.
func (d *Database) AcquireS3ObjectLock(ctx context.Context, tx pgx.Tx, accountID int64, contentHash string) error {
	lockID := GetS3ObjectLockID(accountID, contentHash)
	_, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockID)
	return err
}

// IsS3ObjectOrphan performs a fast query inside a transaction to double-check
// if any active messages or pending uploads exist for the given S3 object.
// Note: It does NOT explicitly check for (uploaded = FALSE AND expunged_at IS NULL),
// because such records inherently imply a `pending_uploads` row exists that will be
// caught by the pending check, keeping this check computationally lightweight.
func (d *Database) IsS3ObjectOrphan(ctx context.Context, tx pgx.Tx, accountID int64, contentHash string, gracePeriod time.Duration) (bool, error) {
	threshold := time.Now().Add(-gracePeriod).UTC()

	var isOrphan bool
	err := tx.QueryRow(ctx, `
		SELECT 
			(active.found IS NULL AND recent.found IS NULL AND pending.found IS NULL) as is_orphan
		FROM 
			(SELECT 1 as dummy) d
		LEFT JOIN LATERAL (
			SELECT 1 as found FROM messages m_active
			WHERE m_active.account_id = $1
			  AND m_active.content_hash = $2
			  AND m_active.expunged_at IS NULL
			LIMIT 1
		) active ON true
		LEFT JOIN LATERAL (
			SELECT 1 as found FROM messages m_recent
			WHERE m_recent.account_id = $1
			  AND m_recent.content_hash = $2
			  AND m_recent.expunged_at >= $3
			LIMIT 1
		) recent ON true
		LEFT JOIN LATERAL (
			SELECT 1 as found FROM pending_uploads pu
			WHERE pu.account_id = $1
			  AND pu.content_hash = $2
			LIMIT 1
		) pending ON true
	`, accountID, contentHash, threshold).Scan(&isOrphan)

	return isOrphan, err
}

// s3ObjectLockTimeout bounds acquiring the dedicated connection and taking the
// per-object advisory locks on it. The locks themselves are never waited for.
const s3ObjectLockTimeout = 30 * time.Second

// ExecuteWithLockedS3Orphans runs fn with the subset of objects that are still orphans,
// while holding their per-object advisory locks on one dedicated session connection.
//
// It is the same lock the uploader holds across its S3 PUT and the DB finalization
// (GetS3ObjectLockID, see resilient.ExecuteWithS3ObjectSessionLock), so holding it
// across the orphan re-check and the caller's S3 DELETE is what stops a delete from
// racing an upload of the same body. The lock is session-scoped rather than
// transaction-scoped precisely so the caller's S3 round trip — and the retry backoff
// hiding inside it — does not run inside an open write transaction, pinning a pool
// connection and its locks for the length of a network operation.
//
// Locks are taken with pg_try_advisory_lock and an object whose lock is held is left
// out of this cycle: a held lock means an uploader is writing that body right now, so
// it is not an orphan at all. Never waiting also means this cannot deadlock against the
// uploader, whatever order the batch happens to be in.
func (d *Database) ExecuteWithLockedS3Orphans(ctx context.Context, objects []UserScopedObjectForCleanup, gracePeriod time.Duration, fn func(orphans []UserScopedObjectForCleanup) error) error {
	if len(objects) == 0 {
		return nil
	}

	lockCtx, cancel := context.WithTimeout(ctx, s3ObjectLockTimeout)
	defer cancel()

	conn, err := d.GetWritePool().Acquire(lockCtx)
	if err != nil {
		return fmt.Errorf("failed to acquire connection for S3 object locks: %w", err)
	}
	defer conn.Release()

	lockIDs := make([]int64, len(objects))
	for i, o := range objects {
		lockIDs[i] = GetS3ObjectLockID(o.AccountID, o.ContentHash)
	}

	rows, err := conn.Query(lockCtx, `SELECT pg_try_advisory_lock(id) FROM unnest($1::bigint[]) AS t(id)`, lockIDs)
	if err != nil {
		return fmt.Errorf("failed to lock S3 objects for cleanup: %w", err)
	}
	acquired, err := pgx.CollectRows(rows, pgx.RowTo[bool])
	if err != nil {
		return fmt.Errorf("failed to lock S3 objects for cleanup: %w", err)
	}
	if len(acquired) != len(objects) {
		return fmt.Errorf("failed to lock S3 objects for cleanup: got %d lock results for %d objects", len(acquired), len(objects))
	}

	// unnest preserves array order, so acquired[i] belongs to objects[i]. The same body
	// can appear twice under two addresses; that stacks the advisory lock, so every id
	// is released exactly as many times as it was taken.
	locked := make([]UserScopedObjectForCleanup, 0, len(objects))
	heldIDs := make([]int64, 0, len(objects))
	for i, ok := range acquired {
		if ok {
			locked = append(locked, objects[i])
			heldIDs = append(heldIDs, lockIDs[i])
		}
	}
	defer func() {
		// Detached context: the unlock must fire even if the caller's context expired.
		if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_unlock(id) FROM unnest($1::bigint[]) AS t(id)`, heldIDs); err != nil {
			// A session that may still hold these locks must not go back into the pool,
			// or those objects would be skipped by every future cleanup cycle.
			logger.Error("failed to release S3 object locks - discarding connection", "count", len(heldIDs), "err", err)
			conn.Conn().Close(context.Background())
		}
	}()

	orphans, err := d.filterS3Orphans(lockCtx, conn, locked, gracePeriod)
	if err != nil {
		return err
	}

	return fn(orphans)
}

// filterS3Orphans returns the objects that are still orphans: no active message, none
// expunged within the grace period, and no pending upload. It is the batched form of
// IsS3ObjectOrphan and runs on the connection that holds the locks, so it reads the
// primary — a lagging replica could report a body as unreferenced after a new message
// already claimed it.
func (d *Database) filterS3Orphans(ctx context.Context, conn *pgxpool.Conn, objects []UserScopedObjectForCleanup, gracePeriod time.Duration) ([]UserScopedObjectForCleanup, error) {
	if len(objects) == 0 {
		return nil, nil
	}

	threshold := time.Now().Add(-gracePeriod).UTC()

	accountIDs := make([]int64, len(objects))
	contentHashes := make([]string, len(objects))
	for i, o := range objects {
		accountIDs[i] = o.AccountID
		contentHashes[i] = o.ContentHash
	}

	rows, err := conn.Query(ctx, `
		SELECT DISTINCT c.account_id, c.content_hash
		FROM unnest($1::bigint[], $2::text[]) AS c(account_id, content_hash)
		WHERE NOT EXISTS (
			SELECT 1 FROM messages m
			WHERE m.account_id = c.account_id
			  AND m.content_hash = c.content_hash
			  AND (m.expunged_at IS NULL OR m.expunged_at >= $3)
		)
		AND NOT EXISTS (
			SELECT 1 FROM pending_uploads pu
			WHERE pu.account_id = c.account_id
			  AND pu.content_hash = c.content_hash
		)
	`, accountIDs, contentHashes, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to confirm S3 object orphans: %w", err)
	}

	type accountHash struct {
		accountID int64
		hash      string
	}
	confirmed := make(map[accountHash]struct{}, len(objects))
	for rows.Next() {
		var key accountHash
		if err := rows.Scan(&key.accountID, &key.hash); err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed to scan confirmed S3 object orphan: %w", err)
		}
		confirmed[key] = struct{}{}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to confirm S3 object orphans: %w", err)
	}

	orphans := make([]UserScopedObjectForCleanup, 0, len(confirmed))
	for _, o := range objects {
		if _, ok := confirmed[accountHash{accountID: o.AccountID, hash: o.ContentHash}]; ok {
			orphans = append(orphans, o)
		}
	}
	return orphans, nil
}

// ExpungeOldMessages marks messages older than the specified duration as expunged
// This enables automatic cleanup of old messages based on age restriction
//
// Each call is capped at BATCH_PURGE_SIZE messages so the transaction — and the set of
// mailbox rows it locks — stays bounded. A backlog larger than the cap must be drained
// by the caller over successive calls; a single unbounded statement can exceed the write
// deadline and roll back, making no progress on any cycle.
//
// It returns how many candidates the batch claimed, NOT how many rows the UPDATE
// changed. A concurrent EXPUNGE or MOVE can take a row out from under the batch, and a
// caller that read the resulting short batch as "the backlog is drained" would abandon
// its drain loop after one batch.
func (d *Database) ExpungeOldMessages(ctx context.Context, tx pgx.Tx, olderThan time.Duration) (int64, error) {
	threshold := time.Now().Add(-olderThan).UTC()

	rows, err := tx.Query(ctx, `
		SELECT id, mailbox_id FROM messages
		WHERE created_at < $1 AND expunged_at IS NULL
		ORDER BY created_at
		LIMIT $2
	`, threshold, BATCH_PURGE_SIZE)
	if err != nil {
		return 0, fmt.Errorf("failed to list old messages for expunge: %w", err)
	}

	var messageIDs []int64
	var candidateMailboxIDs []*int64
	mailboxSet := make(map[int64]struct{})
	for rows.Next() {
		var messageID int64
		var mailboxID *int64
		if err := rows.Scan(&messageID, &mailboxID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("failed to scan old message for expunge: %w", err)
		}
		messageIDs = append(messageIDs, messageID)
		candidateMailboxIDs = append(candidateMailboxIDs, mailboxID)
		if mailboxID != nil {
			mailboxSet[*mailboxID] = struct{}{}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("failed to list old messages for expunge: %w", err)
	}

	if len(messageIDs) == 0 {
		return 0, nil
	}

	// Lock the affected mailbox rows (ascending id) before the batch expunge, so the
	// stats triggers serialize against concurrent STORE/EXPUNGE/MOVE on those
	// mailboxes (see lockMailboxStats) and unseen_count cannot drift. Acquiring the
	// mailbox rows first preserves the global lock order (mailbox row → message rows
	// → mailbox_stats via trigger), so this stays deadlock-free against every other
	// path.
	if len(mailboxSet) > 0 {
		mailboxIDs := make([]int64, 0, len(mailboxSet))
		for mailboxID := range mailboxSet {
			mailboxIDs = append(mailboxIDs, mailboxID)
		}
		sort.Slice(mailboxIDs, func(i, j int) bool { return mailboxIDs[i] < mailboxIDs[j] })

		if _, err := tx.Exec(ctx, `SELECT 1 FROM mailboxes WHERE id = ANY($1) ORDER BY id FOR UPDATE`, mailboxIDs); err != nil {
			return 0, fmt.Errorf("failed to lock mailboxes for age-based expunge: %w", err)
		}
	}

	// Expunge only the candidates still sitting in the mailbox that was locked above:
	// mailbox_id can change under us between the candidate SELECT and here (restore, or
	// the ON DELETE SET NULL of a mailbox removal), and expunging a relocated row would
	// run its stats trigger against a mailbox this transaction does not hold. Such a row
	// is left to the next batch, which locks its new mailbox; grabbing that mailbox now
	// would take locks out of ascending id order and could deadlock.
	if _, err := tx.Exec(ctx, `
		UPDATE messages m
		SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
		FROM unnest($1::bigint[], $2::bigint[]) AS c(id, mailbox_id)
		WHERE m.id = c.id
		  AND m.expunged_at IS NULL
		  AND m.mailbox_id IS NOT DISTINCT FROM c.mailbox_id
	`, messageIDs, candidateMailboxIDs); err != nil {
		return 0, fmt.Errorf("failed to expunge old messages: %w", err)
	}

	return int64(len(messageIDs)), nil
}

// GetUserScopedObjectsForCleanup identifies (AccountID, ContentHash) pairs where all messages
// for that user with that hash have been expunged for longer than the grace period.
//
// Uses a bounded scan-window approach: each batch scans a fixed number of rows from
// idx_messages_cleanup_grouping. This ensures predictable execution time and avoids
// timeout errors when there are many expunged rows but few matching the NOT EXISTS criteria.
func (d *Database) GetUserScopedObjectsForCleanup(ctx context.Context, olderThan time.Duration, limit int) ([]UserScopedObjectForCleanup, error) {
	const scanWindowSize = 5000
	const maxBatches = 200                  // Upper bound: scan up to 1M groups total
	const maxRunDuration = 25 * time.Second // Wall-clock cap

	var allCandidates []UserScopedObjectForCleanup

	// Tuple cursor for pagination through the index
	var lastAccountID int64 = -1
	var lastDomain string = ""
	var lastLocalpart string = ""
	var lastHash string = ""

	runDeadline := time.Now().Add(maxRunDuration)
	threshold := time.Now().Add(-olderThan).UTC()

	for batch := 0; batch < maxBatches && len(allCandidates) < limit; batch++ {
		// Respect the per-run time cap
		if time.Now().After(runDeadline) {
			logger.Info("GetUserScopedObjectsForCleanup: reached time limit, returning partial results",
				"found", len(allCandidates), "requested", limit, "batches", batch)
			break
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		query := `
			WITH RECURSIVE scan_window AS (
				(
					SELECT m.account_id, m.s3_domain, m.s3_localpart, m.content_hash
					FROM messages m
					WHERE m.uploaded = TRUE AND m.expunged_at IS NOT NULL
					  AND (m.account_id, m.s3_domain, m.s3_localpart, m.content_hash) > ($1, $2, $3, $4)
					ORDER BY m.account_id, m.s3_domain, m.s3_localpart, m.content_hash
					LIMIT 1
				)
				UNION ALL
				SELECT m.account_id, m.s3_domain, m.s3_localpart, m.content_hash
				FROM scan_window sw
				CROSS JOIN LATERAL (
					SELECT m2.account_id, m2.s3_domain, m2.s3_localpart, m2.content_hash
					FROM messages m2
					WHERE m2.uploaded = TRUE AND m2.expunged_at IS NOT NULL
					  AND (m2.account_id, m2.s3_domain, m2.s3_localpart, m2.content_hash) > (sw.account_id, sw.s3_domain, sw.s3_localpart, sw.content_hash)
					ORDER BY m2.account_id, m2.s3_domain, m2.s3_localpart, m2.content_hash
					LIMIT 1
				) m
			)
			SELECT 
				sw.account_id, sw.s3_domain, sw.s3_localpart, sw.content_hash,
				(active.found IS NULL AND recent.found IS NULL) as is_orphan
			FROM (SELECT * FROM scan_window LIMIT $5) sw
			LEFT JOIN LATERAL (
				SELECT 1 as found FROM messages m_active
				WHERE m_active.account_id = sw.account_id
				  AND m_active.content_hash = sw.content_hash
				  AND m_active.expunged_at IS NULL
				LIMIT 1
			) active ON true
			LEFT JOIN LATERAL (
				SELECT 1 as found FROM messages m_recent
				WHERE m_recent.account_id = sw.account_id
				  AND m_recent.content_hash = sw.content_hash
				  AND m_recent.expunged_at >= $6
				LIMIT 1
			) recent ON true
			ORDER BY sw.account_id, sw.s3_domain, sw.s3_localpart, sw.content_hash
		`

		rows, err := d.GetReadPool().Query(ctx, query, lastAccountID, lastDomain, lastLocalpart, lastHash, scanWindowSize, threshold)
		if err != nil {
			return nil, fmt.Errorf("failed to query user-scoped objects for cleanup: %w", err)
		}

		var batchCandidates []UserScopedObjectForCleanup
		var rowsProcessed int

		for rows.Next() {
			rowsProcessed++
			var candidate UserScopedObjectForCleanup
			var isOrphan bool
			if err := rows.Scan(&candidate.AccountID, &candidate.S3Domain, &candidate.S3Localpart, &candidate.ContentHash, &isOrphan); err != nil {
				rows.Close()
				return nil, fmt.Errorf("failed to scan user-scoped object for cleanup: %w", err)
			}

			// Update cursor
			lastAccountID = candidate.AccountID
			lastDomain = candidate.S3Domain
			lastLocalpart = candidate.S3Localpart
			lastHash = candidate.ContentHash

			if isOrphan {
				batchCandidates = append(batchCandidates, candidate)
			}
		}
		rows.Close()

		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("error iterating user-scoped objects: %w", err)
		}

		// If we processed fewer rows than scanWindowSize, we have reached the end
		if rowsProcessed == 0 {
			break
		}

		if len(batchCandidates) > 0 {
			remaining := limit - len(allCandidates)
			if len(batchCandidates) > remaining {
				batchCandidates = batchCandidates[:remaining]
			}
			allCandidates = append(allCandidates, batchCandidates...)
		}

		// Short sleep between batches to reduce DB pressure
		time.Sleep(10 * time.Millisecond)
	}

	return allCandidates, nil
}

// DeleteExpungedMessagesByS3KeyPartsBatch deletes all expunged message rows
// from the database that match the given batches of S3 key components.
// It does NOT delete from messages_fts, as the content may be shared.
func (d *Database) DeleteExpungedMessagesByS3KeyPartsBatch(ctx context.Context, tx pgx.Tx, candidates []UserScopedObjectForCleanup) (int64, error) {
	if len(candidates) == 0 {
		return 0, nil
	}

	accountIDs := make([]int64, len(candidates))
	s3Domains := make([]string, len(candidates))
	s3Localparts := make([]string, len(candidates))
	contentHashes := make([]string, len(candidates))

	for i, c := range candidates {
		accountIDs[i] = c.AccountID
		s3Domains[i] = c.S3Domain
		s3Localparts[i] = c.S3Localpart
		contentHashes[i] = c.ContentHash
	}

	tag, err := tx.Exec(ctx, `
		DELETE FROM messages m
		USING unnest($1::bigint[], $2::text[], $3::text[], $4::text[]) AS d(account_id, s3_domain, s3_localpart, content_hash)
		WHERE m.account_id = d.account_id
		  AND m.s3_domain = d.s3_domain
		  AND m.s3_localpart = d.s3_localpart
		  AND m.content_hash = d.content_hash
		  AND m.expunged_at IS NOT NULL
	`, accountIDs, s3Domains, s3Localparts, contentHashes)
	if err != nil {
		return 0, fmt.Errorf("failed to batch delete expunged messages: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteMessageByHashAndMailbox deletes message rows from the database that match
// the given AccountID, MailboxID, and ContentHash. This is a hard delete used
// by the importer for the --force-reimport option.
// It returns the number of messages deleted.
func (d *Database) DeleteMessageByHashAndMailbox(ctx context.Context, tx pgx.Tx, accountID int64, mailboxID int64, contentHash string) (int64, error) {
	tag, err := tx.Exec(ctx, `
		DELETE FROM messages
		WHERE account_id = $1 AND mailbox_id = $2 AND content_hash = $3
	`, accountID, mailboxID, contentHash)
	if err != nil {
		return 0, fmt.Errorf("failed to delete message for re-import (account: %d, mailbox: %d, hash: %s): %w", accountID, mailboxID, contentHash, err)
	}
	return tag.RowsAffected(), nil
}

// CleanupFailedUploads deletes message rows and their corresponding pending_uploads
// once nothing can ever upload their bodies any more.
// This prevents orphaned message metadata from accumulating due to persistent upload failures.
//
// Age alone must never be the criterion: the uploader deliberately does not count
// transient S3 errors toward maxAttempts (see server/uploader/worker.go), so during a
// prolonged outage perfectly deliverable messages stay old with their attempts untouched.
//
// Attempts alone are not a criterion either: a pending upload is leased only by the
// instance that created it (AcquireAndLeasePendingUploads filters on instance_id,
// because the body is a file on that node's local disk), so once that instance is
// decommissioned or renamed nothing increments its attempts ever again.
//
// What separates recoverable from lost is whether the node holding the bytes still
// exists, so a message past the grace period is reaped only when no pending upload
// can still deliver it, i.e. every pending_uploads row for it either
//   - has exhausted its attempts, or
//   - belongs to an instance that is provably gone (no heartbeat and no lease within
//     instanceLiveness — see the instance_heartbeats table), or
//   - does not exist at all (e.g. HardDeleteAccounts removed it).
//
// Uncertainty is never enough: an instance with no heartbeat row and no lease at all
// (a build predating instance_heartbeats, an instance not yet started) counts as
// alive, because over-reaping loses mail permanently while under-reaping costs disk.
func (d *Database) CleanupFailedUploads(ctx context.Context, tx pgx.Tx, gracePeriod time.Duration, maxAttempts int, instanceLiveness time.Duration) (int64, error) {
	if maxAttempts <= 0 {
		return 0, fmt.Errorf("failed to cleanup failed uploads: max attempts must be positive, got %d", maxAttempts)
	}
	if instanceLiveness <= 0 {
		return 0, fmt.Errorf("failed to cleanup failed uploads: instance liveness threshold must be positive, got %s", instanceLiveness)
	}

	threshold := time.Now().Add(-gracePeriod).UTC()

	// This single query uses a Common Table Expression (CTE) to perform the deletions
	// in one atomic operation, which is more efficient than separate queries.
	// 1. The `deleted_messages` CTE deletes old, non-uploaded messages that no pending
	//    upload will retry any more, and returns their keys.
	// 2. The `deleted_pending` CTE then uses these keys to remove the corresponding
	//    entries from `pending_uploads`.
	// 3. The `deleted_instances` CTE retires heartbeat rows of long-gone instances, but
	//    only while they own no pending upload at all: as long as one exists, that row
	//    is the evidence that permits reaping it. CTEs see the pre-statement snapshot,
	//    so rows deleted above still count here and are retired a cycle later.
	// The final SELECT returns the count of messages that were deleted.
	//
	// GREATEST ignores NULLs in PostgreSQL, so it yields the most recent evidence that
	// the owning instance existed, and NULL only when there is no evidence at all. That
	// evidence is written with the database clock (heartbeats and leases both use now()),
	// so the liveness cutoff is derived from now() too rather than from this node's clock.
	query := `
		WITH deleted_messages AS (
			DELETE FROM messages m
			WHERE m.uploaded = FALSE AND m.created_at < $1
			  AND NOT EXISTS (
				SELECT 1 FROM pending_uploads pu
				LEFT JOIN instance_heartbeats ih ON ih.instance_id = pu.instance_id
				WHERE pu.content_hash = m.content_hash AND pu.account_id = m.account_id
				  AND pu.attempts < $2
				  AND (GREATEST(ih.last_seen, pu.last_attempt) IS NULL
				       OR GREATEST(ih.last_seen, pu.last_attempt) > now() - $3::interval)
			  )
			RETURNING m.content_hash, m.account_id
		),
		deleted_pending AS (
			DELETE FROM pending_uploads pu
			WHERE (pu.content_hash, pu.account_id) IN (SELECT content_hash, account_id FROM deleted_messages)
		),
		deleted_instances AS (
			DELETE FROM instance_heartbeats ih
			WHERE ih.last_seen < now() - $3::interval
			  AND NOT EXISTS (SELECT 1 FROM pending_uploads pu WHERE pu.instance_id = ih.instance_id)
		)
		SELECT count(*) FROM deleted_messages
	`

	var deletedCount int64
	err := tx.QueryRow(ctx, query, threshold, maxAttempts, instanceLiveness).Scan(&deletedCount)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup failed uploads: %w", err)
	}

	return deletedCount, nil
}

// PruneOldMessageVectors deletes messages_fts rows whose fts_retention has expired.
// Each row holds the FTS search vector (text_body_tsv).
//
// The DELETE uses a CTE with LIMIT to cap each invocation at maxPruneRows rows,
// preventing long-held locks and WAL bloat if fts_retention is shortened dramatically.
// The cleanup worker calls this periodically; remaining rows are pruned on the next cycle.
//
// The range scan uses the idx_messages_fts_sent_date partial index (WHERE sent_date
// IS NOT NULL), so pre-existing rows with NULL sent_date are never selected.
func (d *Database) PruneOldMessageVectors(ctx context.Context, tx pgx.Tx, retention time.Duration) (int64, error) {
	const maxPruneRows = 1_000

	tag, err := tx.Exec(ctx, `
		WITH expired AS (
			SELECT content_hash FROM messages_fts
			WHERE sent_date < (now() - $1::interval)
			ORDER BY sent_date
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		)
		DELETE FROM messages_fts
		WHERE content_hash IN (SELECT content_hash FROM expired)
	`, retention, maxPruneRows)
	if err != nil {
		return 0, fmt.Errorf("failed to prune old message vectors: %w", err)
	}

	return tag.RowsAffected(), nil
}

// GetUnusedFTSHashes finds content_hash values in messages_fts that are no longer referenced
// by any message row at all. These are candidates for early cleanup even before TTL expires.
//
// Uses a bounded scan-window approach to limit query duration.
func (d *Database) GetUnusedFTSHashes(ctx context.Context, limit int) ([]string, error) {
	const scanWindowSize = 5000
	const maxBatches = 200
	const maxRunDuration = 30 * time.Second

	var allHashes []string
	var lastHash string
	runDeadline := time.Now().Add(maxRunDuration)

	for batch := 0; batch < maxBatches && len(allHashes) < limit; batch++ {
		if time.Now().After(runDeadline) {
			logger.Info("GetUnusedFTSHashes: reached time limit, returning partial results",
				"found", len(allHashes), "requested", limit, "batches", batch)
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		query := `
			WITH scan_window AS (
				SELECT mc.content_hash
				FROM messages_fts mc
				WHERE mc.content_hash > $1
				ORDER BY mc.content_hash
				LIMIT $2
			)
			SELECT
				COALESCE((SELECT MAX(content_hash) FROM scan_window), '') AS window_end,
				ARRAY(
					SELECT sw.content_hash
					FROM scan_window sw
					LEFT JOIN LATERAL (
						SELECT 1 as found
						FROM messages m
						WHERE m.content_hash = sw.content_hash
						LIMIT 1
					) active_msg ON true
					WHERE active_msg.found IS NULL
				) AS orphan_hashes
		`

		var windowEnd string
		var batchHashes []string
		err := d.GetReadPool().QueryRow(ctx, query, lastHash, scanWindowSize).Scan(&windowEnd, &batchHashes)
		if err != nil {
			return nil, fmt.Errorf("failed to query unused FTS hashes: %w", err)
		}

		if windowEnd == "" {
			break
		}

		lastHash = windowEnd

		if len(batchHashes) > 0 {
			remaining := limit - len(allHashes)
			if len(batchHashes) > remaining {
				batchHashes = batchHashes[:remaining]
			}
			allHashes = append(allHashes, batchHashes...)
		}

		time.Sleep(10 * time.Millisecond)
	}

	return allHashes, nil
}

// DeleteMessagesFTSByHashBatch deletes multiple rows from the messages_fts table.
//
// Each hash is re-validated inside the deleting transaction, the way the S3 orphan
// path re-checks with IsS3ObjectOrphan. The caller's list comes from GetUnusedFTSHashes,
// a read-pool scan allowed to run for tens of seconds, and delivery reuses an existing
// row for a hash it re-delivers (INSERT ... ON CONFLICT (content_hash) DO NOTHING), so a
// hash that was unreferenced when it was scanned can carry a live message by now.
// Deleting it would leave that message unsearchable forever, with no error anywhere.
func (d *Database) DeleteMessagesFTSByHashBatch(ctx context.Context, tx pgx.Tx, contentHashes []string) (int64, error) {
	if len(contentHashes) == 0 {
		return 0, nil
	}
	tag, err := tx.Exec(ctx, `
		DELETE FROM messages_fts f
		WHERE f.content_hash = ANY($1)
		  AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.content_hash = f.content_hash)
	`, contentHashes)
	if err != nil {
		return 0, fmt.Errorf("failed to batch delete from messages_fts: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CleanupSoftDeletedAccounts permanently deletes accounts that have been soft-deleted
// for longer than the grace period
func (d *Database) CleanupSoftDeletedAccounts(ctx context.Context, tx pgx.Tx, gracePeriod time.Duration) (int64, error) {
	threshold := time.Now().Add(-gracePeriod).UTC()

	// Get accounts that have been soft-deleted longer than the grace period
	rows, err := tx.Query(ctx, `
		SELECT id 
		FROM accounts 
		WHERE deleted_at IS NOT NULL AND deleted_at < $1
		ORDER BY deleted_at ASC
		LIMIT 50
	`, threshold)
	if err != nil {
		return 0, fmt.Errorf("failed to query soft-deleted accounts: %w", err)
	}
	defer rows.Close()

	var accountsToDelete []int64
	for rows.Next() {
		var accountID int64
		if err := rows.Scan(&accountID); err != nil {
			return 0, fmt.Errorf("failed to scan account ID for cleanup: %w", err)
		}
		accountsToDelete = append(accountsToDelete, accountID)
	}

	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("error iterating soft-deleted accounts: %w", err)
	}

	if len(accountsToDelete) == 0 {
		return 0, nil
	}

	// Perform the first stage of deletion in a single batch transaction
	if err := d.HardDeleteAccounts(ctx, tx, accountsToDelete); err != nil {
		// If the batch fails, we can't be sure which accounts were processed.
		// Log the error and return. The next run will pick them up.
		logger.Error("failed to hard delete account batch", "err", err)
		return 0, err
	}

	totalDeleted := int64(len(accountsToDelete))

	if totalDeleted > 0 {
		logger.Info("cleaned up soft-deleted accounts that exceeded grace period", "count", totalDeleted)
	}

	return totalDeleted, nil
}

// SoftDeletedMailbox identifies a tombstoned mailbox awaiting background hard-deletion.
type SoftDeletedMailbox struct {
	ID        int64
	AccountID int64 // owner; DeleteMailbox gates on this
}

// ListSoftDeletedMailboxes returns up to limit mailboxes the IMAP DELETE path marked
// with deleted_at at least gracePeriod ago (two-phase mailbox deletion), oldest first.
//
// This is a fast, read-only query. The actual hard delete of each mailbox (the heavy
// per-message expunge + row removal) is performed by the caller in a SEPARATE
// transaction per mailbox — see ResilientDatabase.PurgeSoftDeletedMailboxesWithRetry.
// Batching many large mailboxes into one transaction would risk exceeding the write
// deadline and rolling back the whole batch every tick (a poison pill that never makes
// progress, since tombstones are processed oldest-first).
func (d *Database) ListSoftDeletedMailboxes(ctx context.Context, gracePeriod time.Duration, limit int) ([]SoftDeletedMailbox, error) {
	threshold := time.Now().Add(-gracePeriod).UTC()

	rows, err := d.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT id, account_id
		FROM mailboxes
		WHERE deleted_at IS NOT NULL AND deleted_at < $1
		ORDER BY deleted_at ASC
		LIMIT $2
	`, threshold, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query soft-deleted mailboxes: %w", err)
	}
	defer rows.Close()

	var result []SoftDeletedMailbox
	for rows.Next() {
		var m SoftDeletedMailbox
		if err := rows.Scan(&m.ID, &m.AccountID); err != nil {
			return nil, fmt.Errorf("failed to scan soft-deleted mailbox: %w", err)
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

// HardDeleteAccounts performs the first stage of permanent deletion for a batch of accounts.
// It expunges all their messages and deletes associated data like mailboxes, sieve scripts, etc.
// It does NOT delete the account or credential rows themselves, as they are needed for S3 cleanup.
func (d *Database) HardDeleteAccounts(ctx context.Context, tx pgx.Tx, accountIDs []int64) error {
	if len(accountIDs) == 0 {
		return nil
	}

	// Get all mailbox IDs for the accounts being deleted to lock them in a consistent order.
	var mailboxIDs []int64
	rows, err := tx.Query(ctx, "SELECT id FROM mailboxes WHERE account_id = ANY($1)", accountIDs)
	if err != nil {
		return fmt.Errorf("failed to query mailbox IDs for locking: %w", err)
	}
	mailboxIDs, err = pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return fmt.Errorf("failed to collect mailbox IDs for locking: %w", err)
	}

	// Sort the IDs to ensure a consistent lock acquisition order.
	sort.Slice(mailboxIDs, func(i, j int) bool { return mailboxIDs[i] < mailboxIDs[j] })

	// Lock the mailbox rows (ascending id, deterministic) before expunging their
	// messages. This serializes against concurrent EXPUNGE/STORE/MOVE on the same
	// mailboxes (which lock the mailbox row first too — see lockMailboxStats),
	// keeping unseen_count maintenance race-free, and replaces the previous
	// pg_advisory lock to avoid the global advisory-keyspace collision.
	if len(mailboxIDs) > 0 {
		if _, err := tx.Exec(ctx, "SELECT 1 FROM mailboxes WHERE id = ANY($1) ORDER BY id FOR UPDATE", mailboxIDs); err != nil {
			return fmt.Errorf("failed to acquire locks for account deletion: %w", err)
		}
	}

	// Mark all messages as expunged BEFORE deleting their mailboxes. Order matters:
	// messages.mailbox_id is ON DELETE SET NULL, and the maintain_mailbox_stats_messages
	// trigger UPSERTs a mailbox_stats row for any still-active message that gets detached
	// by that SET NULL. If the mailbox row is already gone (deleted first), that UPSERT
	// violates mailbox_stats_mailbox_id_fkey and aborts the whole purge transaction.
	// Expunging first means the SET NULL pass only touches already-expunged rows, which the
	// trigger ignores. This also signals the next cleanup phase to remove the S3 objects.
	_, err = tx.Exec(ctx, `
		UPDATE messages
		SET expunged_at = now(), expunged_modseq = nextval('messages_modseq')
		WHERE account_id = ANY($1) AND expunged_at IS NULL
	`, accountIDs)
	if err != nil {
		return fmt.Errorf("failed to expunge messages for batch deletion: %w", err)
	}

	// Use = ANY($1) for efficient batch operations
	batchOps := []struct {
		tableName string
		query     string
	}{
		{"vacation_responses", "DELETE FROM vacation_responses WHERE account_id = ANY($1)"},
		{"sieve_scripts", "DELETE FROM sieve_scripts WHERE account_id = ANY($1)"},
		{"pending_uploads", "DELETE FROM pending_uploads WHERE account_id = ANY($1)"},
		{"mailboxes", "DELETE FROM mailboxes WHERE account_id = ANY($1)"},
	}

	for _, op := range batchOps {
		if _, err := tx.Exec(ctx, op.query, accountIDs); err != nil {
			return fmt.Errorf("failed to batch delete from %s: %w", op.tableName, err)
		}
	}

	return nil
}

// GetDanglingAccountsForFinalDeletion finds accounts that are marked as deleted and have no
// messages left. Once all messages (and their corresponding S3 objects) are cleaned up,
// the account's master record is safe to be permanently removed.
func (d *Database) GetDanglingAccountsForFinalDeletion(ctx context.Context, limit int) ([]int64, error) {
	rows, err := d.GetReadPool().Query(ctx, `
		SELECT a.id
		FROM accounts a
		WHERE a.deleted_at IS NOT NULL
		AND NOT EXISTS (SELECT 1 FROM messages WHERE account_id = a.id)
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query for dangling accounts: %w", err)
	}
	defer rows.Close()

	var accountIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan dangling account id: %w", err)
		}
		accountIDs = append(accountIDs, id)
	}
	return accountIDs, rows.Err()
}

// FinalizeAccountDeletions permanently deletes a batch of accounts and their credentials.
// This should only be called on dangling accounts that have no other dependencies.
func (d *Database) FinalizeAccountDeletions(ctx context.Context, tx pgx.Tx, accountIDs []int64) (int64, error) {
	if len(accountIDs) == 0 {
		return 0, nil
	}

	// First, delete credentials associated with the accounts.
	_, err := tx.Exec(ctx, "DELETE FROM credentials WHERE account_id = ANY($1)", accountIDs)
	if err != nil {
		return 0, fmt.Errorf("failed to batch delete credentials during finalization: %w", err)
	}

	// Finally, delete the accounts themselves.
	// The ON DELETE RESTRICT on messages provides a final safety check.
	result, err := tx.Exec(ctx, "DELETE FROM accounts WHERE id = ANY($1)", accountIDs)
	if err != nil {
		return 0, fmt.Errorf("failed to finalize batch deletion of accounts: %w", err)
	}

	return result.RowsAffected(), nil
}

// CleanupOldHealthStatuses removes health status records that haven't been updated
// for longer than the specified retention period. This is useful for removing
// records of decommissioned servers.
func (d *Database) CleanupOldHealthStatuses(ctx context.Context, tx pgx.Tx, retention time.Duration) (int64, error) {
	cutoffTime := time.Now().Add(-retention)

	query := `DELETE FROM health_status WHERE updated_at < $1`

	result, err := tx.Exec(ctx, query, cutoffTime)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old health statuses: %w", err)
	}

	return result.RowsAffected(), nil
}

// GetMessagesForMailboxAndChildren retrieves all messages for a mailbox and its children
// This is used by the admin tool for immediate purging of messages
func (d *Database) GetMessagesForMailboxAndChildren(ctx context.Context, accountID int64, mailboxID int64, mailboxPath string) ([]Message, error) {
	query := `
		SELECT
			m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart,
			m.uploaded, ms.flags, ms.custom_flags, m.internal_date, m.size,
			m.created_modseq, ms.updated_modseq, m.expunged_modseq, 0 as seqnum,
			ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.account_id = $1
		  AND (mb.id = $2 OR mb.path LIKE $3 || '%')
		ORDER BY m.id
	`

	rows, err := d.GetReadPool().Query(ctx, query, accountID, mailboxID, mailboxPath)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages for mailbox and children: %w", err)
	}
	defer rows.Close()

	return scanMessages(rows, false)
}

// PurgeMessagesByIDs permanently deletes messages by their IDs
// This is a hard delete used by the admin tool for immediate purging
func (d *Database) PurgeMessagesByIDs(ctx context.Context, messageIDs []int64) (int64, error) {
	if len(messageIDs) == 0 {
		return 0, nil
	}

	tx, err := d.GetWritePool().Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(context.Background())

	result, err := tx.Exec(ctx, `DELETE FROM messages WHERE id = ANY($1)`, messageIDs)
	if err != nil {
		return 0, fmt.Errorf("failed to purge messages: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("failed to commit purge transaction: %w", err)
	}

	return result.RowsAffected(), nil
}

// GetMessagesForAccount retrieves all messages for an account
// This is used by the admin tool to identify S3 objects before purging
// Returns only the minimal fields needed to construct S3 keys
func (d *Database) GetMessagesForAccount(ctx context.Context, accountID int64) ([]Message, error) {
	query := `
		SELECT
			m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart,
			m.uploaded, ms.flags, ms.custom_flags, m.internal_date, m.size,
			m.created_modseq, ms.updated_modseq, m.expunged_modseq, 0 as seqnum,
			ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
		FROM messages m
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.account_id = $1
		ORDER BY m.id
	`

	rows, err := d.GetReadPool().Query(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages for account: %w", err)
	}
	defer rows.Close()

	return scanMessages(rows, false)
}

// ExpungeAllMessagesForAccount marks all messages for an account as expunged
// This is the first step in account deletion - marks messages for cleanup
// The actual deletion from S3 and DB happens via GetUserScopedObjectsForCleanup
func (d *Database) ExpungeAllMessagesForAccount(ctx context.Context, accountID int64) (int64, error) {
	tx, err := d.GetWritePool().Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(context.Background())

	result, err := tx.Exec(ctx, `
		UPDATE messages
		SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
		WHERE account_id = $1 AND expunged_at IS NULL
	`, accountID)
	if err != nil {
		return 0, fmt.Errorf("failed to expunge messages: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("failed to commit expunge transaction: %w", err)
	}

	return result.RowsAffected(), nil
}

// GetUserScopedObjectsForAccount retrieves all expunged messages for a specific account
// Use gracePeriod=0 for immediate cleanup (admin purge), >0 for normal cleanup worker
//
// SAFETY: This function is account-isolated by design:
// - Filters by account_id in WHERE clause
// - Returns only S3 objects for messages belonging to the specified account
// - Safe to delete returned S3 objects without affecting other accounts because:
//  1. Email addresses are globally unique (UNIQUE INDEX on credentials.address)
//  2. S3 keys = <s3_domain>/<s3_localpart>/<content_hash> = <email_domain>/<email_localpart>/<hash>
//  3. Different accounts → different email addresses → different S3 paths
//  4. Even if same content_hash, different email → different S3 object
func (d *Database) GetUserScopedObjectsForAccount(ctx context.Context, accountID int64, gracePeriod time.Duration, limit int) ([]UserScopedObjectForCleanup, error) {
	threshold := time.Now().Add(-gracePeriod).UTC()
	rows, err := d.GetReadPool().Query(ctx, `
		SELECT account_id, s3_domain, s3_localpart, content_hash
		FROM messages
		WHERE account_id = $1
		GROUP BY account_id, s3_domain, s3_localpart, content_hash
		HAVING bool_and(uploaded = TRUE AND expunged_at IS NOT NULL AND expunged_at < $2)
		LIMIT $3;
	`, accountID, threshold, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query for user-scoped objects for account cleanup: %w", err)
	}
	defer rows.Close()

	var result []UserScopedObjectForCleanup
	for rows.Next() {
		var candidate UserScopedObjectForCleanup
		if err := rows.Scan(&candidate.AccountID, &candidate.S3Domain, &candidate.S3Localpart, &candidate.ContentHash); err != nil {
			return nil, fmt.Errorf("failed to scan user-scoped object for cleanup: %w", err)
		}
		result = append(result, candidate)
	}
	return result, rows.Err()
}

// GetAllUploadedObjectsForAccount retrieves ALL uploaded S3 objects for a specific account
// regardless of expunge status. Used for account purging when messages might already be deleted from DB.
//
// SAFETY: This function is account-isolated by design (same guarantees as GetUserScopedObjectsForAccount)
func (d *Database) GetAllUploadedObjectsForAccount(ctx context.Context, accountID int64, limit int) ([]UserScopedObjectForCleanup, error) {
	rows, err := d.GetReadPool().Query(ctx, `
		SELECT account_id, s3_domain, s3_localpart, content_hash
		FROM messages
		WHERE account_id = $1 AND uploaded = TRUE
		GROUP BY account_id, s3_domain, s3_localpart, content_hash
		LIMIT $2;
	`, accountID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query for all uploaded objects for account: %w", err)
	}
	defer rows.Close()

	var result []UserScopedObjectForCleanup
	for rows.Next() {
		var candidate UserScopedObjectForCleanup
		if err := rows.Scan(&candidate.AccountID, &candidate.S3Domain, &candidate.S3Localpart, &candidate.ContentHash); err != nil {
			return nil, fmt.Errorf("failed to scan uploaded object for cleanup: %w", err)
		}
		result = append(result, candidate)
	}
	return result, rows.Err()
}

// PurgeMailboxesForAccount permanently deletes all mailboxes for an account
// This is a hard delete used by the admin tool for immediate account purging
func (d *Database) PurgeMailboxesForAccount(ctx context.Context, accountID int64) error {
	tx, err := d.GetWritePool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(context.Background())

	// Expunge any still-active messages before deleting their mailboxes. The
	// messages.mailbox_id FK is ON DELETE SET NULL, and the maintain_mailbox_stats_messages
	// trigger UPSERTs a mailbox_stats row for an active message detached that way; if the
	// mailbox row is already deleted, that UPSERT violates mailbox_stats_mailbox_id_fkey.
	// Callers (e.g. domain purge) normally expunge first, so this is usually a no-op, but
	// it keeps this hard-delete helper self-safe against a bare DELETE FROM mailboxes.
	if _, err = tx.Exec(ctx, `
		UPDATE messages
		SET expunged_at = now(), expunged_modseq = nextval('messages_modseq')
		WHERE account_id = $1 AND expunged_at IS NULL
	`, accountID); err != nil {
		return fmt.Errorf("failed to expunge messages before purging mailboxes: %w", err)
	}

	_, err = tx.Exec(ctx, `DELETE FROM mailboxes WHERE account_id = $1`, accountID)
	if err != nil {
		return fmt.Errorf("failed to purge mailboxes: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit purge transaction: %w", err)
	}

	return nil
}

// PurgeCredentialsForAccount permanently deletes all credentials for an account
// This is a hard delete used by the admin tool for immediate account purging
func (d *Database) PurgeCredentialsForAccount(ctx context.Context, accountID int64) error {
	tx, err := d.GetWritePool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(context.Background())

	_, err = tx.Exec(ctx, `DELETE FROM credentials WHERE account_id = $1`, accountID)
	if err != nil {
		return fmt.Errorf("failed to purge credentials: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit purge transaction: %w", err)
	}

	return nil
}

// PurgeAccount permanently deletes an account
// This is a hard delete used by the admin tool for immediate account purging
// Note: All associated data (messages, mailboxes, credentials) should be deleted first
func (d *Database) PurgeAccount(ctx context.Context, accountID int64) error {
	tx, err := d.GetWritePool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(context.Background())

	_, err = tx.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, accountID)
	if err != nil {
		return fmt.Errorf("failed to purge account: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit purge transaction: %w", err)
	}

	return nil
}
