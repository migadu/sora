package db

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestS3BodyClaimContinuityOverlapAndLoss(t *testing.T) {
	d := setupTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	hash := fmt.Sprintf("claim-overlap-%d", time.Now().UnixNano())
	holder, err := d.BeginAdvisoryLockTx(ctx)
	require.NoError(t, err)
	defer holder.Release()
	require.NoError(t, holder.LockS3ObjectsShared(ctx, 1, []string{hash}))
	claim := holder.S3BodyClaimContext(ctx, []string{hash})
	// Self-check must not recursively acquire the holder mutex.
	require.NoError(t, holder.CheckS3BodyClaims(claim, []string{hash}))
	inner, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer inner.Rollback(ctx)
	require.NoError(t, LockS3ObjectsSharedInTx(context.WithoutCancel(claim), inner, 1, []string{hash}))
	holder.Release()
	var granted bool
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, GetS3ObjectLockID(1, hash)).Scan(&granted))
	require.False(t, granted, "inner commit must remain protected after a successful overlap")
	require.NoError(t, inner.Commit(ctx))
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, GetS3ObjectLockID(1, hash)).Scan(&granted))
	require.True(t, granted)
	later, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer later.Rollback(ctx)
	require.ErrorIs(t, LockS3ObjectsSharedInTx(context.WithoutCancel(claim), later, 1, []string{hash}), ErrS3BodyClaimLost, "a completed DELETE could fit before this later lock even with no remaining intent")
}

func TestS3BodyClaimContinuityRejectsWrongHashAndWriterFence(t *testing.T) {
	d := setupTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	hash := fmt.Sprintf("claim-bound-%d", time.Now().UnixNano())
	holder, err := d.BeginAdvisoryLockTx(ctx)
	require.NoError(t, err)
	defer holder.Release()
	require.NoError(t, holder.LockS3ObjectsShared(ctx, 1, []string{hash}))
	claim := holder.S3BodyClaimContext(ctx, []string{hash})
	tx, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.ErrorIs(t, LockS3ObjectsSharedInTx(claim, tx, 1, []string{hash + "-unobserved"}), ErrS3BodyClaimLost)
	require.NoError(t, tx.Rollback(ctx))
	d.FenceAdvisoryLocks(errors.New("writer changed"))
	tx, err = d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	require.ErrorIs(t, LockS3ObjectsSharedInTx(claim, tx, 1, []string{hash}), ErrS3BodyClaimLost)
}
