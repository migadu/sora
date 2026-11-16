package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
)

// ErrS3BodyClaimLost means bytes observed under an earlier holder cannot be used
// to admit uploaded metadata. A later, already completed DELETE may have cleared
// its intent; merely acquiring a new lock does not prove those old bytes survived.
var ErrS3BodyClaimLost = fmt.Errorf("S3 body claim continuity was lost: %w", consts.ErrDBNotFound)

type s3BodyClaimContextKey struct{}
type s3BodyClaim struct {
	holder *AdvisoryLockTx
	hashes map[string]struct{}
}

// S3BodyClaimContext binds storage work to this exact holder and hash set. A write
// transaction taking the shared locks must synchronously verify the old holder
// while both overlap, then retain its own locks through commit. Context values
// survive WithoutCancel, so atomic completion cannot accidentally discard this fence.
func (l *AdvisoryLockTx) S3BodyClaimContext(ctx context.Context, hashes []string) context.Context {
	set := make(map[string]struct{}, len(hashes))
	for _, h := range hashes {
		set[h] = struct{}{}
	}
	return context.WithValue(ctx, s3BodyClaimContextKey{}, s3BodyClaim{l, set})
}

func checkS3BodyClaimContinuity(ctx context.Context, tx pgx.Tx, hashes []string) error {
	claim, ok := ctx.Value(s3BodyClaimContextKey{}).(s3BodyClaim)
	if !ok {
		return nil
	}
	for _, h := range hashes {
		if _, ok := claim.hashes[h]; !ok {
			return fmt.Errorf("unlocked hash %s: %w", h, ErrS3BodyClaimLost)
		}
	}
	if err := claim.holder.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrS3BodyClaimLost, err)
	}
	// On the holder itself, run already owns its mutex and proves its transaction;
	// recursively pinging it would deadlock. Compare the transaction itself, never
	// its pooled connection, which can be reused for another transaction.
	// Other write transactions must ping it.
	if tx != claim.holder.tx {
		if err := claim.holder.Ping(ctx); err != nil {
			return fmt.Errorf("%w: %w", ErrS3BodyClaimLost, err)
		}
	}
	return nil
}

// lockS3SourceClaims freezes the source accounts against a rekey before reading
// their hashes, acquires all corresponding body locks, and lets COPY/MOVE reread
// source rows from a fresh READ COMMITTED snapshot. No changed hash can slip from
// the first read into an uploaded copy without having its body lock held.
func lockS3SourceClaims(ctx context.Context, tx pgx.Tx, mailboxID int64, uids *[]imap.UID) error {
	if err := lockRekeySources(ctx, tx, mailboxID, uids); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT content_hash FROM messages WHERE mailbox_id=$1 AND uid=ANY($2) AND expunged_at IS NULL`, mailboxID, uids)
	if err != nil {
		return err
	}
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return err
		}
		hashes = append(hashes, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	return LockS3ObjectsSharedInTx(ctx, tx, 0, hashes)
}
