package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

type readSnapshotTxKey struct{}

// ErrReadSnapshotAborted wraps an error from InReadSavepoint when creating,
// committing, or rolling back the savepoint itself failed, leaving the outer
// snapshot transaction unusable.
var ErrReadSnapshotAborted = errors.New("read snapshot aborted")

// readQuerier is the subset of *pgxpool.Pool / pgx.Tx used by read methods that
// execute either directly against the read pool or inside InReadSnapshot.
type readQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// readQuerier returns the context-bound snapshot transaction when ctx is inside
// InReadSnapshot, and d.GetReadPoolWithContext(ctx) otherwise.
func (d *Database) readQuerier(ctx context.Context) readQuerier {
	if ctx != nil {
		if tx, ok := ctx.Value(readSnapshotTxKey{}).(pgx.Tx); ok && tx != nil {
			return tx
		}
	}
	return d.GetReadPoolWithContext(ctx)
}

// HasReadSnapshot reports whether ctx carries an active InReadSnapshot transaction.
func HasReadSnapshot(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	tx, ok := ctx.Value(readSnapshotTxKey{}).(pgx.Tx)
	return ok && tx != nil
}

// InReadSnapshot runs fn inside a single REPEATABLE READ READ ONLY transaction
// opened on d.GetReadPoolWithContext(ctx) (honouring consts.UseMasterDBKey).
// The first query executed inside fn fixes the PostgreSQL MVCC snapshot that all
// subsequent readQuerier reads in fn observe; the transaction is always rolled
// back when fn returns. The callback context is scoped to fn and must only be
// used with snapshot-aware read methods on this Database.
func (d *Database) InReadSnapshot(ctx context.Context, fn func(ctx context.Context) error) error {
	if HasReadSnapshot(ctx) {
		return fn(ctx)
	}
	tx, err := d.GetReadPoolWithContext(ctx).BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return fmt.Errorf("failed to begin read snapshot: %w", err)
	}
	defer tx.Rollback(context.Background())

	return fn(context.WithValue(ctx, readSnapshotTxKey{}, tx))
}

// InReadSavepoint runs fn inside a PostgreSQL SAVEPOINT when ctx is inside
// InReadSnapshot, rolling back to the savepoint on error so an optional or
// fallbackable read that fails with a non-connection SQL error does not leave
// the outer snapshot transaction in SQLSTATE 25P02 (in_failed_sql_transaction).
// Outside InReadSnapshot it calls fn(ctx) directly.
func InReadSavepoint(ctx context.Context, fn func(ctx context.Context) error) error {
	if ctx == nil {
		return fn(ctx)
	}
	tx, ok := ctx.Value(readSnapshotTxKey{}).(pgx.Tx)
	if !ok || tx == nil {
		return fn(ctx)
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrReadSnapshotAborted, err)
	}
	if err := fn(context.WithValue(ctx, readSnapshotTxKey{}, sp)); err != nil {
		if rbErr := sp.Rollback(ctx); rbErr != nil {
			// A failed rollback is the terminal failure. Preserve the statement error
			// diagnostically without hiding a connection failure from error classifiers.
			return fmt.Errorf("%w: rollback failed: %w (statement: %v)", ErrReadSnapshotAborted, rbErr, err)
		}
		return err
	}
	if err := sp.Commit(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrReadSnapshotAborted, err)
	}
	return nil
}
