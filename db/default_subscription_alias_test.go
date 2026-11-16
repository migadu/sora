package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultMailboxSubscriptionAliases(t *testing.T) {
	ctx := context.Background()
	t.Run("canonical physical default with legacy Unicode subscription", func(t *testing.T) {
		d, accountID := setupMailboxTestDatabase(t)
		defer d.Close()
		tx, err := d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, d.CreateDefaultMailboxes(ctx, tx, accountID))
		// Preserve an upgrade state a prior release could leave: the canonical
		// mailbox still exists, but its name-based subscription uses an alias.
		_, err = tx.Exec(ctx, "DELETE FROM subscriptions WHERE account_id=$1 AND LOWER(mailbox_name)=LOWER($2)", accountID, "Junk")
		require.NoError(t, err)
		require.NoError(t, d.Subscribe(ctx, tx, accountID, "Jun\u212A"))
		require.NoError(t, tx.Commit(ctx))
		m, err := d.GetMailboxByName(ctx, accountID, "Jun\u212A")
		require.NoError(t, err)
		require.Equal(t, "Junk", m.Name)
		tx, err = d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, d.SetMailboxSubscribed(ctx, tx, m.ID, accountID, false))
		require.NoError(t, tx.Commit(ctx))
		names, err := d.GetSubscribedMailboxNames(ctx, accountID)
		require.NoError(t, err)
		require.Contains(t, names, "Jun\u212A", "a default's legacy subscription must remain protected")
	})
	t.Run("ordinary Unicode physical mailbox without canonical counterpart", func(t *testing.T) {
		d, accountID := setupMailboxTestDatabase(t)
		defer d.Close()
		tx, err := d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, d.CreateMailbox(ctx, tx, accountID, "Jun\u212A", nil))
		require.NoError(t, d.Subscribe(ctx, tx, accountID, "Jun\u212A"))
		require.NoError(t, tx.Commit(ctx))
		m, err := d.GetMailboxByName(ctx, accountID, "Junk")
		require.NoError(t, err)
		require.Equal(t, "Jun\u212A", m.Name)
		tx, err = d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, d.SetMailboxSubscribed(ctx, tx, m.ID, accountID, false))
		require.NoError(t, tx.Commit(ctx))
		names, err := d.GetSubscribedMailboxNames(ctx, accountID)
		require.NoError(t, err)
		require.NotContains(t, names, "Jun\u212A")
	})
	t.Run("ASCII default ghost stays subscribed", func(t *testing.T) {
		d, accountID := setupMailboxTestDatabase(t)
		defer d.Close()
		tx, err := d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, d.Subscribe(ctx, tx, accountID, "Junk"))
		require.NoError(t, d.Unsubscribe(ctx, tx, accountID, "JUNK"))
		require.NoError(t, tx.Commit(ctx))
		names, err := d.GetSubscribedMailboxNames(ctx, accountID)
		require.NoError(t, err)
		require.Contains(t, names, "Junk")
	})
}
