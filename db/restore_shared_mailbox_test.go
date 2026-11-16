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
// is_shared and the owner's domain (#1289). It came back as a personal mailbox
// (is_shared = false, no owner_domain, no ACL), which LIST shows in the shared namespace
// and SETACL refuses to share. The ACL the mailbox had before it was deleted is gone with
// it and does not come back, and it does not take a live shared parent's ACL either: each
// level the restore recreates gets one entry, the owner with default_rights.
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
			`SELECT mailbox_id FROM messages WHERE id = $1 AND expunged_at IS NULL`, restoredCopyID(t, db, msgID)).Scan(&mailboxID))
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
			// Each recreated level gets the owner entry with default_rights only. The
			// grantee's entry on the deleted Shared/Team is not restored.
			assert.Equal(t, map[string]string{ownerEmail: "lrswipkxte"}, acl(m.id), "%s ACL", name)
		}
		assert.Equal(t, root.path, team.path[:len(root.path)], "Shared/Team is linked under Shared")
		assert.Equal(t, team.id, liveIn(msgID), "the message is back in Shared/Team")
	})

	t.Run("under a live shared parent", func(t *testing.T) {
		// Shared/Sales grants the grantee "lr". Shared/Sales/Confidential, created below
		// it, inherits that entry (RFC 4314 section 4, CREATE), and the owner then takes
		// the grantee off it. Once Confidential is deleted and restored, a copy of the
		// parent's entries would let the grantee read the messages it was kept away from.
		require.NoError(t, db.CreateMailboxForUser(ctx, ownerID, "Shared/Sales"))
		require.NoError(t, db.GrantMailboxAccessByIdentifier(ctx, ownerID, granteeEmail, "Shared/Sales", "lr"))
		require.NoError(t, db.CreateMailboxForUser(ctx, ownerID, "Shared/Sales/Confidential"))
		created := mailbox("Shared/Sales/Confidential")
		require.Equal(t, map[string]string{ownerEmail: "lrswipkxte", granteeEmail: "lr"}, acl(created.id),
			"a mailbox created under a shared parent still copies the parent's entries")
		require.NoError(t, db.RevokeMailboxAccessByIdentifier(ctx, created.id, granteeEmail))
		msgID := insertTestMessage(t, db, ownerID, created.id, "Shared/Sales/Confidential", "confidential", "<confidential@example.com>")
		deleteMailbox(ctx, "Shared/Sales/Confidential")

		restore(ctx, "Shared/Sales/Confidential")

		restored := mailbox("Shared/Sales/Confidential")
		assert.True(t, restored.shared, "is_shared")
		assert.Equal(t, "example.com", restored.domain, "owner_domain")
		assert.Equal(t, map[string]string{ownerEmail: "lrswipkxte"}, acl(restored.id),
			"the owner only: no copy of the parent's entries")
		assert.Equal(t, map[string]string{ownerEmail: "lrswipkxte", granteeEmail: "lr"}, acl(mailbox("Shared/Sales").id),
			"the parent's ACL is unchanged")
		assert.Equal(t, restored.id, liveIn(msgID), "the message is back in Shared/Sales/Confidential")
	})

	t.Run("levels recreated under a live shared parent", func(t *testing.T) {
		// Shared/Ops is live and grants the grantee "lr"; Archive and Archive/2025 below it
		// are both gone. Each level the restore recreates gets the owner entry only.
		require.NoError(t, db.CreateMailboxForUser(ctx, ownerID, "Shared/Ops"))
		require.NoError(t, db.GrantMailboxAccessByIdentifier(ctx, ownerID, granteeEmail, "Shared/Ops", "lr"))
		require.NoError(t, db.CreateMailboxForUser(ctx, ownerID, "Shared/Ops/Archive/2025"))
		msgID := insertTestMessage(t, db, ownerID, mailbox("Shared/Ops/Archive/2025").id, "Shared/Ops/Archive/2025", "2025", "<ops-2025@example.com>")
		deleteMailbox(ctx, "Shared/Ops/Archive/2025")
		deleteMailbox(ctx, "Shared/Ops/Archive")

		restore(ctx, "Shared/Ops/Archive/2025")

		archive, year := mailbox("Shared/Ops/Archive"), mailbox("Shared/Ops/Archive/2025")
		for name, m := range map[string]mailboxRow{"Shared/Ops/Archive": archive, "Shared/Ops/Archive/2025": year} {
			assert.True(t, m.shared, "%s is_shared", name)
			assert.Equal(t, "example.com", m.domain, "%s owner_domain", name)
			assert.Equal(t, map[string]string{ownerEmail: "lrswipkxte"}, acl(m.id), "%s ACL", name)
		}
		assert.Equal(t, archive.path, year.path[:len(archive.path)], "Archive/2025 is linked under Archive")
		assert.Equal(t, year.id, liveIn(msgID), "the message is back in Shared/Ops/Archive/2025")
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
