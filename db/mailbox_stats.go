package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

// lockMailboxStats serializes unseen_count maintenance for a mailbox by taking a
// transaction-scoped row lock (SELECT ... FOR UPDATE) on its mailboxes row.
//
// The mailbox_stats.unseen_count cache is maintained by TWO independent
// statement-level triggers — maintain_mailbox_stats_messages (on the messages
// table, for expunge/move) and maintain_mailbox_stats_state (on message_state,
// for flag changes). Each computes its delta from a cross-table read
// (messages.expunged_at joined against message_state.flags). Under READ
// COMMITTED, two concurrent transactions operating on the same mailbox can each
// read the seen/expunged state at independent points in time, so a single
// logical "this message stopped being unseen" event gets charged twice — once
// by the flag trigger (unseen→seen) and once by the expunge trigger (reading the
// stale unseen flag). Each such race drifts unseen_count by -1, eventually
// underflowing on busy mailboxes (notably INBOX).
//
// Locking the mailbox's row at the START of every unseen-mutating transaction
// forces the two triggers' cross-table reads to observe a consistent committed
// state, making the additive deltas exact. Two deliberate choices:
//
//  1. We lock the parent mailboxes row, NOT the mailbox_stats row. The stats
//     triggers UPDATE mailbox_stats at the END of their statement (AFTER trigger),
//     so every existing path acquires that row LAST (message rows → stats row).
//     Locking mailbox_stats first would invert that order and deadlock against
//     trigger-driven bulk paths (mailbox/account delete, age-based expunge).
//     The mailboxes row is never touched by the stats triggers, so it acts as a
//     separate serialization point acquired first, preserving one global lock
//     order (mailbox row → message rows → stats row) across ALL paths. It also
//     always exists (no empty-mailbox edge case) and is already the lock APPEND
//     takes via its highest_uid UPDATE.
//  2. We use a row lock, NOT a pg_advisory lock. The advisory keyspace is global
//     and shared with the cleanup/migration locks (CLEANUP_ADVISORY_LOCK_ID,
//     SoraAdvisoryLockID); a BIGSERIAL mailbox id equal to one of those constants
//     would collide. A row lock cannot.
//
// FOR UPDATE does not block plain SELECT readers, so STATUS/LIST stay
// non-blocking. Callers MUST acquire this before any other row locks in the same
// transaction; MoveMessages and the delete paths lock multiple mailbox rows in
// ascending id order for the same reason (see lockMailboxStatsPair).
func lockMailboxStats(ctx context.Context, tx pgx.Tx, mailboxID int64) error {
	if _, err := tx.Exec(ctx, "SELECT 1 FROM mailboxes WHERE id = $1 FOR UPDATE", mailboxID); err != nil {
		return fmt.Errorf("failed to lock mailbox %d for stats maintenance: %w", mailboxID, err)
	}
	return nil
}

// lockMailboxStatsPair locks the mailboxes rows for two mailboxes in a
// deterministic (ascending id) order, so concurrent operations touching the same
// pair (e.g. MOVE A→B and MOVE B→A) cannot deadlock. See lockMailboxStats for the
// rationale on what this protects. When both ids are equal, a single row is
// locked once.
func lockMailboxStatsPair(ctx context.Context, tx pgx.Tx, a, b int64) error {
	lo, hi := a, b
	if hi < lo {
		lo, hi = hi, lo
	}
	if err := lockMailboxStats(ctx, tx, lo); err != nil {
		return err
	}
	if hi != lo {
		if err := lockMailboxStats(ctx, tx, hi); err != nil {
			return err
		}
	}
	return nil
}

// RecomputeMailboxUnseen recomputes unseen_count for a single mailbox from the
// authoritative source of truth (active, unseen message_state rows) and writes
// it back into the mailbox_stats cache. It is the self-healing counterpart to
// the incremental trigger maintenance: where the triggers can drift under
// concurrency, this restores the exact value.
//
// It takes the per-mailbox advisory lock first so the COUNT(*) is consistent
// with any in-flight expunge/flag transaction. If the mailbox_stats row does
// not exist yet (mailbox never had any messages), this is a no-op and returns 0
// — GetMailboxSummary already COALESCEs a missing row to 0.
func (d *Database) RecomputeMailboxUnseen(ctx context.Context, tx pgx.Tx, mailboxID int64) (int64, error) {
	if err := lockMailboxStats(ctx, tx, mailboxID); err != nil {
		return 0, err
	}

	var unseen int64
	err := tx.QueryRow(ctx, fmt.Sprintf(`
		UPDATE mailbox_stats ms
		SET unseen_count = (
			SELECT COUNT(*)
			FROM message_state mst
			JOIN messages m ON m.id = mst.message_id AND m.mailbox_id = mst.mailbox_id
			WHERE mst.mailbox_id = $1 AND (mst.flags & %d) = 0 AND m.expunged_at IS NULL
		),
		updated_at = now()
		WHERE ms.mailbox_id = $1
		RETURNING unseen_count
	`, FlagSeen), mailboxID).Scan(&unseen)
	if err != nil {
		if err == pgx.ErrNoRows {
			// No cache row to repair; effective value is already 0.
			return 0, nil
		}
		return 0, fmt.Errorf("failed to recompute unseen_count for mailbox %d: %w", mailboxID, err)
	}
	return unseen, nil
}

// ReconcileNegativeMailboxStats finds every mailbox whose cached unseen_count has
// underflowed below zero and recomputes it from the authoritative source. Each
// mailbox is repaired in its own short transaction (holding the per-mailbox lock
// only briefly) so this never blocks live traffic on a long-running scan.
//
// This both heals any pre-existing drift and acts as a continuous safety net for
// residual drift. It is intended to be called periodically by the cleanup worker
// under the cluster-wide cleanup lock, so only one node runs it at a time.
func (d *Database) ReconcileNegativeMailboxStats(ctx context.Context) (int64, error) {
	rows, err := d.GetReadPoolWithContext(ctx).Query(ctx,
		"SELECT mailbox_id FROM mailbox_stats WHERE unseen_count < 0")
	if err != nil {
		return 0, fmt.Errorf("failed to list mailboxes with negative unseen_count: %w", err)
	}
	var mailboxIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("failed to scan mailbox id during reconcile: %w", err)
		}
		mailboxIDs = append(mailboxIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("error iterating mailboxes for reconcile: %w", err)
	}

	var fixed int64
	for _, mailboxID := range mailboxIDs {
		if err := ctx.Err(); err != nil {
			return fixed, err
		}
		tx, err := d.GetWritePool().Begin(ctx)
		if err != nil {
			logger.Warn("Reconcile: failed to begin tx for mailbox unseen repair", "mailbox_id", mailboxID, "err", err)
			continue
		}
		unseen, err := d.RecomputeMailboxUnseen(ctx, tx, mailboxID)
		if err != nil {
			_ = tx.Rollback(ctx)
			logger.Warn("Reconcile: failed to recompute unseen_count", "mailbox_id", mailboxID, "err", err)
			continue
		}
		if err := tx.Commit(ctx); err != nil {
			logger.Warn("Reconcile: failed to commit unseen_count repair", "mailbox_id", mailboxID, "err", err)
			continue
		}
		fixed++
		logger.Info("Reconcile: repaired negative unseen_count", "mailbox_id", mailboxID, "unseen_count", unseen)
	}

	if fixed > 0 {
		metrics.DBQueriesTotal.WithLabelValues("mailbox_unseen_reconcile", "success", "write").Add(float64(fixed))
	}
	return fixed, nil
}
