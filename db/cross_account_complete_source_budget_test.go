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
