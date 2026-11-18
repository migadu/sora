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
// source read, and tells the two kinds of COPY/MOVE apart.
//
// A command is budgeted when it re-keys a row to another account or carries
// destObjects. It is limited to MaxCrossAccountBodies distinct bodies, counting every
// source body, including legacy rows already owned by its destination, and its
// distinct source hashes are returned for the caller to lock. No global body lock is
// taken here.
//
// Every other command copies rows within their own accounts (all sources belong to
// destAccountID, or it is a MOVE within one mailbox, which keeps each row's account and
// S3 key). It is not limited, so no hashes are returned for it: it must never take a
// lock per body (see lockS3SourceClaims).
func sourceBodyClaims(ctx context.Context, tx pgx.Tx, mailboxID, destMailboxID, destAccountID int64, uids *[]imap.UID, destObjects []string) (hashes []string, budgeted bool, err error) {
	if err := lockRekeySources(ctx, tx, mailboxID, uids); err != nil {
		return nil, false, err
	}
	// A MOVE within one mailbox retains its existing account/S3 identities.
	if mailboxID == destMailboxID {
		return nil, false, nil
	}
	if len(destObjects) == 0 {
		// A row's account never changes (a rekey renames its hash only), so this answer
		// holds for the rows the caller reads afterwards.
		var cross bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM messages WHERE mailbox_id=$1 AND uid=ANY($2) AND expunged_at IS NULL AND account_id IS DISTINCT FROM $3)`, mailboxID, uids, destAccountID).Scan(&cross); err != nil {
			return nil, false, err
		}
		if !cross {
			return nil, false, nil
		}
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT content_hash FROM messages WHERE mailbox_id=$1 AND uid=ANY($2) AND expunged_at IS NULL`, mailboxID, uids)
	if err != nil {
		return nil, false, err
	}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return nil, false, err
		}
		hashes = append(hashes, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	bodies := make(map[string]struct{}, min(len(hashes)+len(destObjects), MaxCrossAccountBodies+1))
	for _, list := range [][]string{hashes, destObjects} {
		for _, hash := range list {
			bodies[hash] = struct{}{}
			if len(bodies) > MaxCrossAccountBodies {
				return nil, false, ErrCrossAccountBodyLimit
			}
		}
	}
	return hashes, true, nil
}

// CheckCopyMoveBodyBudget checks the complete current source under account rekey
// guards in the actual write transaction, before any destination body lock or
// storage callback. Caller-supplied rekey-only maps cannot establish this budget.
// Pure same-account operations retain their existing uncapped policy.
func (db *Database) CheckCopyMoveBodyBudget(ctx context.Context, tx pgx.Tx, srcMailboxID, destMailboxID, destAccountID int64, uids *[]imap.UID, destObjects []string) error {
	_, _, err := sourceBodyClaims(ctx, tx, srcMailboxID, destMailboxID, destAccountID, uids, destObjects)
	return err
}

// lockS3SourceClaims protects the bodies of a COPY/MOVE's source rows until the new
// rows commit, and refuses a body with an open deletion intent.
//
// A budgeted command (sourceBodyClaims) takes the shared body lock of every distinct
// source hash, at most MaxCrossAccountBodies of them, and rereads its sources from a
// fresh READ COMMITTED snapshot while the account guards and body locks remain held
// through commit.
//
// A command within one account takes NO body lock. It is not limited and not batched,
// and each advisory lock is an entry in PostgreSQL's server-wide lock table until the
// transaction ends: one lock per body would let a single "move this folder" fill the
// table and fail every session with "out of shared memory" (SQLSTATE 53200). Its
// bodies are protected by its source rows instead. A new row has the account, S3 key
// and hash of the source row it is copied from, and no deleter retires a body while
// its account has a live row of that hash (filterS3Orphans), so the body stands as
// long as that reference never lapses between the command's read and its commit:
//
//   - MoveMessages locks its source rows FOR UPDATE, then expunges them and inserts
//     their replacements in the same transaction: the source is live until the commit
//     and the new row from it.
//   - CopyMessages locks its uploaded source rows FOR SHARE until the commit, so no
//     expunge or delete of one can commit in between, and marks a copy uploaded only if
//     its source was among them. Every other copy starts not uploaded, with a pending
//     upload: it claims no object.
//
// Row locks are kept in the rows and take no lock-table entry. A rekey is held off by
// the account guard; a deleter working for another account that shares the key counts
// rows in any state, and the source row exists throughout.
//
// What such a command no longer does is make an exclusive holder of the body lock wait
// for it. The deleters do not need that (above). The missing-object repair, which
// changes the rows it finds under that lock, reads them again until it has them all
// (MarkMessagesAsNotUploadedIfAbsent).
func lockS3SourceClaims(ctx context.Context, tx pgx.Tx, mailboxID, destMailboxID, destAccountID int64, uids *[]imap.UID, destObjects []string) error {
	hashes, budgeted, err := sourceBodyClaims(ctx, tx, mailboxID, destMailboxID, destAccountID, uids, destObjects)
	if err != nil {
		return err
	}
	if budgeted {
		return LockS3ObjectsSharedInTx(ctx, tx, 0, hashes)
	}
	return checkS3SourceBodyIntents(ctx, tx, mailboxID, uids)
}

// checkS3SourceBodyIntents is the deletion-intent check of CheckS3BodyClaims for a
// COPY/MOVE within one account, made on the source rows themselves: such a command may
// name any number of bodies, so their hashes are neither read into memory nor sent back
// as a parameter. A body with an open intent is refused, as for every other admission.
func checkS3SourceBodyIntents(ctx context.Context, tx pgx.Tx, mailboxID int64, uids *[]imap.UID) error {
	var isolation string
	var quarantined bool
	if err := tx.QueryRow(ctx, `
		SELECT current_setting('transaction_isolation'), EXISTS (
			SELECT 1 FROM s3_body_delete_intents di
			JOIN messages m ON m.content_hash = di.content_hash
			WHERE m.mailbox_id = $1 AND m.uid = ANY($2) AND m.expunged_at IS NULL)`,
		mailboxID, uids).Scan(&isolation, &quarantined); err != nil {
		return fmt.Errorf("check S3 body deletion intents: %w", err)
	}
	if isolation != "read committed" {
		return fmt.Errorf("S3 body admission requires READ COMMITTED: %w", ErrS3BodyQuarantined)
	}
	if quarantined {
		return ErrS3BodyQuarantined
	}
	return nil
}
