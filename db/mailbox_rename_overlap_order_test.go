package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/require"
)

// The immediate unique name index checks each changed row. Legal physical heap
// order must not decide whether overlapping old/new descendant names can move.
func TestRenameMailbox_OverlappingNamesInAdverseHeapOrder(t *testing.T) {
	d := setupTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	for _, tc := range []struct {
		name, old, new string
		names          []string
		order          []int
		want           []string
	}{
		{"shortening", "Pane/Sub", "Pane", []string{"Pane/Sub", "Pane/Sub/Sub", "Pane/Sub/Sub/Sub"}, []int{2, 1, 0}, []string{"Pane", "Pane/Sub", "Pane/Sub/Sub"}},
		{"lengthening", "Pane", "Pane/Sub", []string{"Pane", "Pane/Sub/Sub", "Pane/Sub/Sub/Sub"}, []int{1, 2, 0}, []string{"Pane/Sub", "Pane/Sub/Sub/Sub", "Pane/Sub/Sub/Sub/Sub"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := createTestAccount(t, d, fmt.Sprintf("overlap-order-%s-%d@example.com", tc.name, time.Now().UnixNano()), "password")
			tx, err := d.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)
			// Reserve normal sequence IDs, then insert the valid hierarchy in the
			// adverse physical order. No schema/heap rewrite affects other accounts.
			rows, err := tx.Query(ctx, "SELECT nextval('mailboxes_id_seq') FROM generate_series(1,4)")
			require.NoError(t, err)
			ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
			require.NoError(t, err)
			paths := []string{helpers.GetMailboxPath("", ids[0]), "", ""}
			paths[1] = helpers.GetMailboxPath(paths[0], ids[1])
			paths[2] = helpers.GetMailboxPath(paths[1], ids[2])
			created := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
			for _, i := range tc.order {
				_, err = tx.Exec(ctx, "INSERT INTO mailboxes(id,account_id,name,path,uid_validity,created_at) VALUES($1,$2,$3,$4,$5,$6)", ids[i], account, tc.names[i], paths[i], 101+i, created)
				require.NoError(t, err)
			}
			// Historical descendants must retain the old UPDATE's scope as well.
			_, err = tx.Exec(ctx, "INSERT INTO mailboxes(id,account_id,name,path,uid_validity,created_at,deleted_at) VALUES($1,$2,$3,$4,104,$5,$5)", ids[3], account, tc.old+"/Deleted", helpers.GetMailboxPath(paths[0], ids[3]), created)
			require.NoError(t, err)
			_, err = tx.Exec(ctx, "INSERT INTO mailbox_acls(mailbox_id,account_id,identifier,rights) VALUES($1,$2,$3,'lr')", ids[1], account, fmt.Sprintf("owner-%d", account))
			require.NoError(t, err)
			var aclBefore string
			require.NoError(t, tx.QueryRow(ctx, "SELECT row_to_json(a)::text FROM mailbox_acls a WHERE mailbox_id=$1", ids[1]).Scan(&aclBefore))
			// Force a heap scan so both orders above deterministically reach UPDATE.
			_, err = tx.Exec(ctx, "SET LOCAL enable_bitmapscan=off; SET LOCAL enable_indexscan=off")
			require.NoError(t, err)
			require.NoError(t, d.RenameMailbox(ctx, tx, ids[0], account, tc.new, nil))
			for i, id := range ids[:3] {
				var name, path string
				var validity int64
				var gotCreated time.Time
				require.NoError(t, tx.QueryRow(ctx, "SELECT name,path,uid_validity,created_at FROM mailboxes WHERE id=$1 AND account_id=$2", id, account).Scan(&name, &path, &validity, &gotCreated))
				require.Equal(t, tc.want[i], name)
				require.Equal(t, paths[i], path)
				require.Equal(t, int64(101+i), validity)
				require.True(t, created.Equal(gotCreated))
			}
			var deletedName string
			require.NoError(t, tx.QueryRow(ctx, "SELECT name FROM mailboxes WHERE id=$1 AND deleted_at IS NOT NULL", ids[3]).Scan(&deletedName))
			require.Equal(t, tc.new+"/Deleted", deletedName)
			var aclAfter string
			require.NoError(t, tx.QueryRow(ctx, "SELECT row_to_json(a)::text FROM mailbox_acls a WHERE mailbox_id=$1", ids[1]).Scan(&aclAfter))
			require.Equal(t, aclBefore, aclAfter)
			require.NoError(t, tx.Commit(ctx))
		})
	}
}
