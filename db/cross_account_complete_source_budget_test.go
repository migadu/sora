package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

// The direct SQL APIs cannot rely on a caller's rekey-only hash map either.
// Refusal must occur before body admission or UID allocation, even when only one
// selected row is rekeyed and all the others already belong to the destination.
func TestDirectCopyMoveBudgetRejectsAlreadyOwnedSourceBodies(t *testing.T) {
	d, _, a, inbox := setupCleanerTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	var b int64
	inTx(t, d, func(tx pgx.Tx) {
		var err error
		b, err = d.CreateAccount(ctx, tx, CreateAccountRequest{Email: fmt.Sprintf("budget-%d@example.net", time.Now().UnixNano()), Password: "password123", IsPrimary: true, HashType: "bcrypt"})
		require.NoError(t, err)
	})
	dest := createRestageMailbox(t, ctx, d, b, "Budget")
	const n = MaxCrossAccountBodies + 1
	prefix := fmt.Sprintf("direct-budget-%d-", time.Now().UnixNano())
	_, err := d.GetWritePool().Exec(ctx, `INSERT INTO messages(account_id,mailbox_id,uid,content_hash,s3_domain,s3_localpart,uploaded,recipients_json,message_id,sent_date,internal_date,size,body_structure,created_modseq) SELECT CASE WHEN g=1 THEN $1::bigint ELSE $2::bigint END,$3,g,$4||g,'example.com','budget',TRUE,'[]','<'||$4||g||'@example.com>',now(),now(),100,'\x00',nextval('messages_modseq') FROM generate_series(1,$5::int)g`, a, b, inbox, prefix, n)
	require.NoError(t, err)
	_, err = d.GetWritePool().Exec(ctx, `UPDATE mailboxes SET highest_uid=$2 WHERE id=$1`, inbox, n)
	require.NoError(t, err)
	uids := make([]imap.UID, n)
	for i := range uids {
		uids[i] = imap.UID(i + 1)
	}
	for _, mode := range []string{"COPY", "MOVE"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := d.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)
			if mode == "COPY" {
				_, _, err = d.CopyMessages(ctx, tx, &uids, inbox, dest, b, "example.net", "owner", "budget", map[imap.UID]string{1: prefix + "1"}, nil)
			} else {
				_, err = d.MoveMessages(ctx, tx, &uids, inbox, dest, b, "example.net", "owner", "budget", map[imap.UID]string{1: prefix + "1"}, nil)
			}
			require.ErrorIs(t, err, ErrCrossAccountBodyLimit)
			var bodyLocks, nextUID, rows int
			require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory' AND objsubid=1`).Scan(&bodyLocks))
			require.Zero(t, bodyLocks, "rekey-account guards are allowed; global body locks are not")
			require.NoError(t, tx.QueryRow(ctx, `SELECT highest_uid FROM mailboxes WHERE id=$1`, dest).Scan(&nextUID))
			require.Zero(t, nextUID)
			require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM messages WHERE mailbox_id=$1`, dest).Scan(&rows))
			require.Zero(t, rows)
		})
	}
}

// CheckCopyMoveBodyBudget must also enforce MaxCrossAccountBodies on destObjects
// when cross == false (for example, when all cross-account source rows were
// concurrently expunged before sourceBodyClaims ran, or a caller passes oversized
// destObjects on same-owner rows).
func TestCheckCopyMoveBodyBudgetRejectsOversizedDestObjectsWithoutCrossAccountSources(t *testing.T) {
	d, _, a, inbox := setupCleanerTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	var b int64
	inTx(t, d, func(tx pgx.Tx) {
		var err error
		b, err = d.CreateAccount(ctx, tx, CreateAccountRequest{Email: fmt.Sprintf("destobj-budget-%d@example.net", time.Now().UnixNano()), Password: "password123", IsPrimary: true, HashType: "bcrypt"})
		require.NoError(t, err)
	})
	dest := createRestageMailbox(t, ctx, d, b, "DestObjectsBudget")

	const n = MaxCrossAccountBodies + 1
	destObjects := make([]string, n)
	uids := make([]imap.UID, n)
	prefix := fmt.Sprintf("destobj-%d-", time.Now().UnixNano())
	for i := range n {
		destObjects[i] = fmt.Sprintf("%s%d", prefix, i+1)
		uids[i] = imap.UID(i + 1)
	}

	t.Run("all cross-account rows concurrently expunged", func(t *testing.T) {
		tx, err := d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		err = d.CheckCopyMoveBodyBudget(ctx, tx, inbox, dest, b, &uids, destObjects)
		require.ErrorIs(t, err, ErrCrossAccountBodyLimit)
	})

	t.Run("live same-owner row plus destObjects exceeds cap", func(t *testing.T) {
		_, err := d.GetWritePool().Exec(ctx, `INSERT INTO messages(account_id,mailbox_id,uid,content_hash,s3_domain,s3_localpart,uploaded,recipients_json,message_id,sent_date,internal_date,size,body_structure,created_modseq) VALUES ($1,$2,1,$3,'example.net','owner',TRUE,'[]',$4,now(),now(),100,'\x00',nextval('messages_modseq'))`,
			b, inbox, prefix+"owned", "<"+prefix+"owned@example.net>")
		require.NoError(t, err)
		_, err = d.GetWritePool().Exec(ctx, `UPDATE mailboxes SET highest_uid=1 WHERE id=$1`, inbox)
		require.NoError(t, err)
		_ = a

		tx, err := d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		oneUID := []imap.UID{1}
		err = d.CheckCopyMoveBodyBudget(ctx, tx, inbox, dest, b, &oneUID, destObjects[:MaxCrossAccountBodies])
		require.ErrorIs(t, err, ErrCrossAccountBodyLimit)
	})
}

// Same-mailbox MoveMessages preserves every row's existing account_id and S3 key,
// so legacy contributor rows (sourceAccountID != destAccountID) must succeed when
// sourceHashes is nil or stale after a concurrent content-hash rekey.
func TestSameMailboxMoveIgnoresStaleOrNilSourceHashesForLegacyContributorRows(t *testing.T) {
	d, _, a, _ := setupCleanerTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	var b int64
	inTx(t, d, func(tx pgx.Tx) {
		var err error
		b, err = d.CreateAccount(ctx, tx, CreateAccountRequest{Email: fmt.Sprintf("samebox-move-%d@example.net", time.Now().UnixNano()), Password: "password123", IsPrimary: true, HashType: "bcrypt"})
		require.NoError(t, err)
	})
	shared := createRestageMailbox(t, ctx, d, b, "Shared/Team")
	hash := fmt.Sprintf("legacy-contrib-%d", time.Now().UnixNano())
	_, err := d.GetWritePool().Exec(ctx, `INSERT INTO messages(account_id,mailbox_id,mailbox_path,uid,content_hash,s3_domain,s3_localpart,uploaded,recipients_json,message_id,sent_date,internal_date,size,body_structure,created_modseq) VALUES ($1,$2,'Shared/Team',1,$3,'example.com','contrib',TRUE,'[]',$4,now(),now(),100,'\x00',nextval('messages_modseq'))`,
		a, shared, hash, "<"+hash+"@example.com>")
	require.NoError(t, err)
	_, err = d.GetWritePool().Exec(ctx, `UPDATE mailboxes SET highest_uid=1 WHERE id=$1`, shared)
	require.NoError(t, err)

	// 1) nil sourceHashes (direct caller / gated same-mailbox MOVE).
	tx1, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx1.Rollback(ctx)
	uids1 := []imap.UID{1}
	uidMap1, err := d.MoveMessages(ctx, tx1, &uids1, shared, shared, b, "example.net", "owner", "samebox", nil, nil)
	require.NoError(t, err)
	require.Equal(t, map[imap.UID]imap.UID{1: 2}, uidMap1)
	require.NoError(t, tx1.Commit(ctx))

	// 2) stale sourceHashes (simulating a concurrent import rekey on a legacy row).
	tx2, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)
	uids2 := []imap.UID{2}
	uidMap2, err := d.MoveMessages(ctx, tx2, &uids2, shared, shared, b, "example.net", "owner", "samebox", map[imap.UID]string{2: "stale-hash-before-rekey"}, nil)
	require.NoError(t, err)
	require.Equal(t, map[imap.UID]imap.UID{2: 3}, uidMap2)
	require.NoError(t, tx2.Commit(ctx))

	var gotAccount int64
	var gotDomain, gotLocal, gotHash string
	var gotUploaded bool
	require.NoError(t, d.GetWritePool().QueryRow(ctx,
		`SELECT account_id, s3_domain, s3_localpart, content_hash, uploaded FROM messages WHERE mailbox_id=$1 AND expunged_at IS NULL`,
		shared).Scan(&gotAccount, &gotDomain, &gotLocal, &gotHash, &gotUploaded))
	require.Equal(t, a, gotAccount)
	require.Equal(t, "example.com", gotDomain)
	require.Equal(t, "contrib", gotLocal)
	require.Equal(t, hash, gotHash)
	require.True(t, gotUploaded)
}
