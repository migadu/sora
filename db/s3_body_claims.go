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

// sourceBodyClaims freezes the selected accounts against rekey before a fresh
// source read. A cross-account operation budgets every source body, including
// legacy rows already owned by its destination. No global body lock is taken here.
func sourceBodyClaims(ctx context.Context, tx pgx.Tx, mailboxID, destMailboxID, destAccountID int64, uids *[]imap.UID, destObjects []string) ([]string, error) {
	if err := lockRekeySources(ctx, tx, mailboxID, uids); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT content_hash, bool_or(account_id IS DISTINCT FROM $3) FROM messages WHERE mailbox_id=$1 AND uid=ANY($2) AND expunged_at IS NULL GROUP BY content_hash`, mailboxID, uids, destAccountID)
	if err != nil {
		return nil, err
	}
	var hashes []string
	cross := false
	for rows.Next() {
		var h string
		var rekeyed bool
		if err := rows.Scan(&h, &rekeyed); err != nil {
			rows.Close()
			return nil, err
		}
		hashes = append(hashes, h)
		cross = cross || rekeyed
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// A MOVE within one mailbox retains its existing account/S3 identities.
	if cross && mailboxID != destMailboxID {
		bodies := make(map[string]struct{}, min(len(hashes)+len(destObjects), MaxCrossAccountBodies+1))
		for _, list := range [][]string{hashes, destObjects} {
			for _, hash := range list {
				bodies[hash] = struct{}{}
				if len(bodies) > MaxCrossAccountBodies {
					return nil, ErrCrossAccountBodyLimit
				}
			}
		}
	}
	return hashes, nil
}

// CheckCopyMoveBodyBudget checks the complete current source under account rekey
// guards in the actual write transaction, before any destination body lock or
// storage callback. Caller-supplied rekey-only maps cannot establish this budget.
// Pure same-account operations retain their existing uncapped policy.
func (db *Database) CheckCopyMoveBodyBudget(ctx context.Context, tx pgx.Tx, srcMailboxID, destMailboxID, destAccountID int64, uids *[]imap.UID, destObjects []string) error {
	_, err := sourceBodyClaims(ctx, tx, srcMailboxID, destMailboxID, destAccountID, uids, destObjects)
	return err
}

// lockS3SourceClaims budgets the fresh, rekey-stable source before acquiring its
// shared body locks. COPY/MOVE reread from a fresh READ COMMITTED snapshot while
// the account guards and body locks remain held through commit.
func lockS3SourceClaims(ctx context.Context, tx pgx.Tx, mailboxID, destMailboxID, destAccountID int64, uids *[]imap.UID, destObjects []string) error {
	hashes, err := sourceBodyClaims(ctx, tx, mailboxID, destMailboxID, destAccountID, uids, destObjects)
	if err != nil {
		return err
	}
	return LockS3ObjectsSharedInTx(ctx, tx, 0, hashes)
}
