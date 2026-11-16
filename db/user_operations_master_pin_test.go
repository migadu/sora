package db

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
)

func TestMailboxWriteOperationsHonorWriterWhenReplicaLags(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}

	t.Run("personal mailbox created after replica snapshot", func(t *testing.T) {
		master := setupTestDatabase(t)
		t.Cleanup(master.Close)

		ctx := context.Background()
		domain := fmt.Sprintf("uopspin%d.example", time.Now().UnixNano())
		accountID, _ := setupAccountWithInbox(t, master, ctx, "user@"+domain)

		schema := fmt.Sprintf("uops_pin_replica_%d", time.Now().UnixNano())
		_, err := master.GetWritePool().Exec(ctx, "CREATE SCHEMA "+schema)
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = master.GetWritePool().Exec(ctx, "DROP SCHEMA "+schema+" CASCADE") })
		for _, table := range []string{"mailboxes", "subscriptions"} {
			_, err := master.GetWritePool().Exec(ctx, fmt.Sprintf("CREATE TABLE %s.%s AS SELECT * FROM public.%s WHERE account_id = $1", schema, table, table), accountID)
			require.NoError(t, err)
		}

		require.NoError(t, master.CreateMailboxForUser(ctx, accountID, "Projects"))

		replica := newLaggingReplicaPool(t, ctx, schema)
		t.Cleanup(replica.Close)
		split := &Database{WritePool: master.GetWritePool(), ReadPool: replica}

		// Control: the lagging replica does not know about Projects yet.
		_, err = split.GetMailboxByName(ctx, accountID, "Projects")
		require.ErrorIs(t, err, consts.ErrMailboxNotFound)

		require.NoError(t, split.SubscribeToMailbox(ctx, accountID, "Projects"))
		subs, err := master.GetSubscribedMailboxNames(ctx, accountID)
		require.NoError(t, err)
		require.True(t, slices.ContainsFunc(subs, func(n string) bool { return strings.EqualFold(n, "Projects") }))

		require.NoError(t, split.UnsubscribeFromMailbox(ctx, accountID, "Projects"))
		subs, err = master.GetSubscribedMailboxNames(ctx, accountID)
		require.NoError(t, err)
		require.False(t, slices.ContainsFunc(subs, func(n string) bool { return strings.EqualFold(n, "Projects") }))

		require.NoError(t, split.DeleteMailboxForUser(ctx, accountID, "Projects"))
		_, err = master.GetMailboxByName(ctx, accountID, "Projects")
		require.ErrorIs(t, err, consts.ErrMailboxNotFound)
	})

	t.Run("shared mailbox delete checks writer ACL when replica grant lags", func(t *testing.T) {
		master := setupTestDatabase(t)
		t.Cleanup(master.Close)

		baseCtx := context.Background()
		domain := fmt.Sprintf("uopsaclpin%d.example", time.Now().UnixNano())
		sharedCtx := context.WithValue(baseCtx, consts.ConfigContextKey, &config.Config{
			SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/"},
		})

		owner, _ := setupAccountWithInbox(t, master, baseCtx, "owner@"+domain)
		granteeEmail := "grantee@" + domain
		grantee, _ := setupAccountWithInbox(t, master, baseCtx, granteeEmail)

		tx, err := master.GetWritePool().Begin(sharedCtx)
		require.NoError(t, err)
		defer tx.Rollback(baseCtx)
		require.NoError(t, master.CreateMailbox(sharedCtx, tx, owner, "Shared/Cleanup", nil))
		require.NoError(t, tx.Commit(sharedCtx))

		// Replica snapshot sees lookup+read ('lr') only, before delete ('x') is granted.
		require.NoError(t, master.GrantMailboxAccessByIdentifier(sharedCtx, owner, granteeEmail, "Shared/Cleanup", "lr"))

		schema := fmt.Sprintf("uops_acl_replica_%d", time.Now().UnixNano())
		_, err = master.GetWritePool().Exec(baseCtx, "CREATE SCHEMA "+schema)
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = master.GetWritePool().Exec(baseCtx, "DROP SCHEMA "+schema+" CASCADE") })
		for _, table := range []string{"mailboxes", "mailbox_acls", "credentials"} {
			_, err := master.GetWritePool().Exec(baseCtx, fmt.Sprintf("CREATE TABLE %s.%s AS TABLE public.%s", schema, table, table))
			require.NoError(t, err)
		}
		_, err = master.GetWritePool().Exec(baseCtx, fmt.Sprintf(`CREATE FUNCTION %s.has_mailbox_right(bigint, bigint, text) RETURNS boolean LANGUAGE sql AS 'SELECT false'`, schema))
		require.NoError(t, err)

		// Grant delete ('x') on the writer after the replica snapshot.
		require.NoError(t, master.GrantMailboxAccessByIdentifier(sharedCtx, owner, granteeEmail, "Shared/Cleanup", "lrx"))

		replica := newLaggingReplicaPool(t, baseCtx, schema)
		t.Cleanup(replica.Close)
		split := &Database{WritePool: master.GetWritePool(), ReadPool: replica}

		mbox, err := master.GetMailboxByName(sharedCtx, owner, "Shared/Cleanup")
		require.NoError(t, err)
		hasRightOnReplica, err := split.CheckMailboxPermission(baseCtx, mbox.ID, grantee, ACLRightDelete)
		require.NoError(t, err)
		require.False(t, hasRightOnReplica, "control: replica must report no delete right")

		require.NoError(t, split.DeleteMailboxForUser(sharedCtx, grantee, "Shared/Cleanup"))
		_, err = master.GetMailboxByName(sharedCtx, owner, "Shared/Cleanup")
		require.ErrorIs(t, err, consts.ErrMailboxNotFound)
	})
}
