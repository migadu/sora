package resilient

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
)

// ListRekeyCandidatesWithRetry lists an account's stored bodies in key order; see
// db.ListRekeyCandidates.
func (rd *ResilientDatabase) ListRekeyCandidatesWithRetry(ctx context.Context, accountID int64, after db.ContentObject, limit int) ([]db.ContentObject, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).ListRekeyCandidates(ctx, accountID, after, limit)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.([]db.ContentObject), nil
}

// RekeyContentHashWithRetry moves an account's rows from one stored body to the same bytes
// under newHash; see db.RekeyContentHash. A retry repeats the whole transaction, which is
// safe: an attempt that rolled back changed nothing, and an unknown commit is not retried.
func (rd *ResilientDatabase) RekeyContentHashWithRetry(ctx context.Context, accountID int64, obj db.ContentObject, newHash string) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).RekeyContentHash(ctx, tx, accountID, obj, newHash)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op, db.ErrRekeyUploadPending)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

// IsContentObjectReferencedWithRetry reports whether anything still points at a stored
// body; see db.IsContentObjectReferenced.
func (rd *ResilientDatabase) IsContentObjectReferencedWithRetry(ctx context.Context, obj db.ContentObject) (bool, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).IsContentObjectReferenced(ctx, obj)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}
