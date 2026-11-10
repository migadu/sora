package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestACLReadsHonorMasterDBPin(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	master := setupTestDatabase(t)
	t.Cleanup(master.Close)
	ctx := context.Background()
	domain := fmt.Sprintf("aclpin%d.example", time.Now().UnixNano())
	owner, mailboxID := setupAccountWithInbox(t, master, ctx, "owner@"+domain)
	reader, _ := setupAccountWithInbox(t, master, ctx, "reader@"+domain)
	_, err := master.GetWritePool().Exec(ctx, `UPDATE mailboxes SET name='Shared/ACL', is_shared=TRUE, owner_domain=$2 WHERE id=$1`, mailboxID, domain)
	require.NoError(t, err)
	require.NoError(t, master.GrantMailboxAccessByIdentifier(ctx, owner, "reader@"+domain, "Shared/ACL", "lri"))
	require.NoError(t, master.GrantMailboxAccessByIdentifier(ctx, owner, AnyoneIdentifier, "Shared/ACL", "te"))

	// Independent read-pool state models lag in ownership, direct grants,
	// primary identity and anyone grants. Every ACL read must honor the pin.
	schema := fmt.Sprintf("acl_pin_replica_%d", time.Now().UnixNano())
	_, err = master.GetWritePool().Exec(ctx, "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = master.GetWritePool().Exec(ctx, "DROP SCHEMA "+schema+" CASCADE") })
	for _, table := range []string{"mailboxes", "mailbox_acls", "credentials"} {
		_, err := master.GetWritePool().Exec(ctx, fmt.Sprintf("CREATE TABLE %s.%s AS TABLE public.%s", schema, table, table))
		require.NoError(t, err)
	}
	_, err = master.GetWritePool().Exec(ctx, fmt.Sprintf("UPDATE %s.mailboxes SET account_id=$1 WHERE id=$2", schema), reader, mailboxID)
	require.NoError(t, err)
	_, err = master.GetWritePool().Exec(ctx, fmt.Sprintf("UPDATE %s.mailbox_acls SET rights='' WHERE mailbox_id=$1 AND (account_id=$2 OR identifier='anyone')", schema), mailboxID, reader)
	require.NoError(t, err)
	_, err = master.GetWritePool().Exec(ctx, fmt.Sprintf("UPDATE %s.credentials SET address='reader@other.example' WHERE account_id=$1", schema), reader)
	require.NoError(t, err)
	// A replica's permission function can likewise report a revoked/stale grant.
	_, err = master.GetWritePool().Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s.has_mailbox_right(bigint, bigint, text) RETURNS boolean LANGUAGE sql AS 'SELECT false'`, schema))
	require.NoError(t, err)
	replica := newLaggingReplicaPool(t, ctx, schema)
	t.Cleanup(replica.Close)
	split := &Database{WritePool: master.GetWritePool(), ReadPool: replica}
	pinned := context.WithValue(ctx, consts.UseMasterDBKey, true)

	t.Run("ACL listing", func(t *testing.T) {
		stale, err := split.GetMailboxACLs(ctx, mailboxID)
		require.NoError(t, err)
		fresh, err := master.GetMailboxACLs(ctx, mailboxID)
		require.NoError(t, err)
		require.NotEqual(t, fresh, stale)
		got, err := split.GetMailboxACLs(pinned, mailboxID)
		require.NoError(t, err)
		assert.Equal(t, fresh, got)
	})
	t.Run("permission", func(t *testing.T) {
		stale, err := split.CheckMailboxPermission(ctx, mailboxID, reader, ACLRightInsert)
		require.NoError(t, err)
		require.False(t, stale)
		got, err := split.CheckMailboxPermission(pinned, mailboxID, reader, ACLRightInsert)
		require.NoError(t, err)
		assert.True(t, got)
	})
	t.Run("move rights", func(t *testing.T) {
		i, d, e, err := split.CheckMoveRights(ctx, mailboxID, mailboxID, reader)
		require.NoError(t, err)
		require.False(t, i || d || e)
		i, d, e, err = split.CheckMoveRights(pinned, mailboxID, mailboxID, reader)
		require.NoError(t, err)
		assert.True(t, i && d && e)
	})
	t.Run("effective direct and anyone rights", func(t *testing.T) {
		stale, err := split.GetUserMailboxRights(ctx, mailboxID, reader)
		require.NoError(t, err)
		require.Equal(t, AllACLRights, stale, "replica has stale ownership")
		got, err := split.GetUserMailboxRights(pinned, mailboxID, reader)
		require.NoError(t, err)
		assert.Equal(t, "lrite", got)
	})
}
