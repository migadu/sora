package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRestoreMessages_RecreatesSharedMailboxAsShared: a restore that recreates a deleted
// mailbox in the shared namespace makes it a shared mailbox, as createMailbox makes one:
// is_shared, the owner's domain, and the initial ACL of a new shared mailbox (#1289). It
// came back as a personal mailbox (is_shared = false, no owner_domain, no ACL), which LIST
// shows in the shared namespace and SETACL refuses to share. The ACL the mailbox had
// before it was deleted is gone with it and does not come back.
func TestRestoreMessages_RecreatesSharedMailboxAsShared(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, ownerID, ownerEmail, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()

	sharedCtx := func(enabled bool) context.Context {
		return context.WithValue(context.Background(), consts.ConfigContextKey, &config.Config{
			SharedMailboxes: config.SharedMailboxesConfig{Enabled: enabled, NamespacePrefix: "Shared/", DefaultRights: "lrswipkxte"},
		})
	}
	ctx := sharedCtx(true)

	granteeEmail := fmt.Sprintf("restore_grantee_%d@example.com", time.Now().UnixNano())
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.CreateAccount(ctx, tx, CreateAccountRequest{Email: granteeEmail, Password: "password123", IsPrimary: true, HashType: "bcrypt"})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	type mailboxRow struct {
		id     int64
		path   string
		shared bool
		domain string
	}
	mailbox := func(name string) mailboxRow {
		t.Helper()
		var m mailboxRow
		require.NoError(t, db.GetWritePool().QueryRow(ctx, `
			SELECT id, path, COALESCE(is_shared, FALSE), COALESCE(owner_domain, '')
			FROM mailboxes WHERE account_id = $1 AND name = $2 AND deleted_at IS NULL`,
			ownerID, name).Scan(&m.id, &m.path, &m.shared, &m.domain), "mailbox %s", name)
		return m
	}
	// The stored entries, not GetMailboxACLs, which reports the owner with every right
	// whatever its row says and so would not show which rights the row was given.
	acl := func(mailboxID int64) map[string]string {
		t.Helper()
		rows, err := db.GetWritePool().Query(ctx, `SELECT identifier, rights FROM mailbox_acls WHERE mailbox_id = $1`, mailboxID)
		require.NoError(t, err)
		defer rows.Close()
		entries := map[string]string{}
		for rows.Next() {
			var identifier, rights string
			require.NoError(t, rows.Scan(&identifier, &rights))
			entries[identifier] = rights
		}
		require.NoError(t, rows.Err())
		return entries
	}
	deleteMailbox := func(ctx context.Context, name string) {
		t.Helper()
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, db.DeleteMailbox(ctx, tx, mailbox(name).id, ownerID))
		require.NoError(t, tx.Commit(ctx))
	}
	restore := func(ctx context.Context, name string) {
		t.Helper()
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		n, err := db.RestoreMessages(ctx, tx, RestoreMessagesParams{Email: ownerEmail, MailboxPath: &name})
		require.NoError(t, err)
		require.Equal(t, int64(1), n, "restored messages of %s", name)
		require.NoError(t, tx.Commit(ctx))
	}
	liveIn := func(msgID int64) int64 {
		t.Helper()
		var mailboxID int64
		require.NoError(t, db.GetWritePool().QueryRow(ctx,
			`SELECT mailbox_id FROM messages WHERE id = $1 AND expunged_at IS NULL`, msgID).Scan(&mailboxID))
		return mailboxID
	}

	t.Run("mailbox and namespace root both gone", func(t *testing.T) {
		require.NoError(t, db.CreateMailboxForUser(ctx, ownerID, "Shared/Team"))
		require.NoError(t, db.GrantMailboxAccessByIdentifier(ctx, ownerID, granteeEmail, "Shared/Team", "lr"))
		msgID := insertTestMessage(t, db, ownerID, mailbox("Shared/Team").id, "Shared/Team", "team", "<team@example.com>")
		deleteMailbox(ctx, "Shared/Team")
		deleteMailbox(ctx, "Shared")

		restore(ctx, "Shared/Team")

		root, team := mailbox("Shared"), mailbox("Shared/Team")
		for name, m := range map[string]mailboxRow{"Shared": root, "Shared/Team": team} {
			assert.True(t, m.shared, "%s is_shared", name)
			assert.Equal(t, "example.com", m.domain, "%s owner_domain", name)
			// The root gets the creator entry with default_rights, and Shared/Team a copy
			// of its shared parent's entries, as IMAP CREATE Shared/Team makes them. The
			// grantee's entry on the deleted Shared/Team is not restored.
			assert.Equal(t, map[string]string{ownerEmail: "lrswipkxte"}, acl(m.id), "%s ACL", name)
		}
		assert.Equal(t, root.path, team.path[:len(root.path)], "Shared/Team is linked under Shared")
		assert.Equal(t, team.id, liveIn(msgID), "the message is back in Shared/Team")
	})

	t.Run("under a live shared parent", func(t *testing.T) {
		require.NoError(t, db.CreateMailboxForUser(ctx, ownerID, "Shared/Sales"))
		require.NoError(t, db.GrantMailboxAccessByIdentifier(ctx, ownerID, granteeEmail, "Shared/Sales", "lr"))
		require.NoError(t, db.CreateMailboxForUser(ctx, ownerID, "Shared/Sales/Q1"))
		require.NoError(t, db.GrantMailboxAccessByIdentifier(ctx, ownerID, granteeEmail, "Shared/Sales/Q1", "lrsw"))
		msgID := insertTestMessage(t, db, ownerID, mailbox("Shared/Sales/Q1").id, "Shared/Sales/Q1", "q1", "<q1@example.com>")
		deleteMailbox(ctx, "Shared/Sales/Q1")

		restore(ctx, "Shared/Sales/Q1")

		q1 := mailbox("Shared/Sales/Q1")
		assert.True(t, q1.shared, "is_shared")
		assert.Equal(t, "example.com", q1.domain, "owner_domain")
		// A copy of the parent's entries now, not the "lrsw" the deleted Q1 granted.
		assert.Equal(t, map[string]string{ownerEmail: "lrswipkxte", granteeEmail: "lr"}, acl(q1.id), "ACL")
		assert.Equal(t, q1.id, liveIn(msgID), "the message is back in Shared/Sales/Q1")
	})

	t.Run("sharing disabled", func(t *testing.T) {
		// With sharing off there is no shared namespace: the name is a personal mailbox,
		// as CREATE makes it.
		off := sharedCtx(false)
		require.NoError(t, db.CreateMailboxForUser(off, ownerID, "Shared/Off"))
		msgID := insertTestMessage(t, db, ownerID, mailbox("Shared/Off").id, "Shared/Off", "off", "<off@example.com>")
		deleteMailbox(off, "Shared/Off")

		restore(off, "Shared/Off")

		m := mailbox("Shared/Off")
		assert.False(t, m.shared, "is_shared")
		assert.Empty(t, m.domain, "owner_domain")
		assert.Empty(t, acl(m.id), "ACL")
		assert.Equal(t, m.id, liveIn(msgID), "the message is back in Shared/Off")
	})
}
