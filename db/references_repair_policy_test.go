package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// An explicit References repair must not become a historical header-presence or
// message-state backfill, and an expunged donor still describes the same raw body.
func TestNullReferencesRepairPreservesForwardOnlyMetadata(t *testing.T) {
	d, _, account, inbox := setupCleanerTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	hash := fmt.Sprintf("refs-policy-%d", time.Now().UnixNano())
	insertKeyedMessage(t, d, account, inbox, 1, hash, "refs-policy", true, time.Now().Add(-time.Hour))
	insertKeyedMessage(t, d, account, inbox, 2, hash, "refs-policy", true, time.Time{})
	var donor, target int64
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT min(id),max(id) FROM messages WHERE mailbox_id=$1 AND content_hash=$2`, inbox, hash).Scan(&donor, &target))
	_, err := d.GetWritePool().Exec(ctx, `UPDATE messages SET "references"=CASE WHEN id=$1 THEN 'root@example.com' END,header_presence=NULL WHERE id=ANY($2)`, donor, []int64{donor, target})
	require.NoError(t, err)
	_, err = d.GetWritePool().Exec(ctx, `DELETE FROM message_state WHERE message_id=$1`, target)
	require.NoError(t, err)
	snapshot := func() string {
		var s string
		require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT jsonb_build_array(m.uid,m.created_modseq,m.header_presence,(SELECT count(*) FROM message_state WHERE message_id=m.id),b.highest_uid,s.highest_modseq,s.message_count)::text FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id LEFT JOIN mailbox_stats s ON s.mailbox_id=b.id WHERE m.id=$1`, target).Scan(&s))
		return s
	}
	before := snapshot()
	batch, err := d.FindNullReferences(ctx, target-1, 1)
	require.NoError(t, err)
	require.Equal(t, []ReferencesFill{{ID: target, References: "root@example.com"}}, batch.Fills)
	inTx(t, d, func(tx pgx.Tx) {
		n, err := d.FillNullReferences(ctx, tx, batch.Fills)
		require.NoError(t, err)
		require.Equal(t, int64(1), n)
	})
	require.Equal(t, before, snapshot(), "repair only the explicitly requested stored References")
	var refs string
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT "references" FROM messages WHERE id=$1`, target).Scan(&refs))
	require.Equal(t, "root@example.com", refs)
}
