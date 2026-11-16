package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
)

// TestCreateDefaultMailboxes_SetsSpecialUse verifies that the default mailboxes
// created for a new account carry the correct RFC 6154 special-use attribute in
// the persisted special_use column (INBOX has none). This is the storage-level
// guarantee behind LIST reporting \Sent/\Drafts/etc. for fresh accounts.
func TestCreateDefaultMailboxes_SetsSpecialUse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()

	email := fmt.Sprintf("test-default-specialuse-%d@example.com", time.Now().UnixNano())
	accountID := createTestAccount(t, db, email, "password")

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateDefaultMailboxes(ctx, tx, accountID))
	require.NoError(t, tx.Commit(ctx))

	rows, err := db.GetReadPool().Query(ctx,
		`SELECT name, COALESCE(special_use, '') FROM mailboxes WHERE account_id = $1 AND deleted_at IS NULL`,
		accountID)
	require.NoError(t, err)
	defer rows.Close()

	got := map[string]string{}
	for rows.Next() {
		var name, specialUse string
		require.NoError(t, rows.Scan(&name, &specialUse))
		got[name] = specialUse
	}
	require.NoError(t, rows.Err())
	t.Logf("default mailboxes special_use: %v", got)

	want := map[string]string{
		"INBOX":   "",
		"Sent":    `\Sent`,
		"Drafts":  `\Drafts`,
		"Archive": `\Archive`,
		"Junk":    `\Junk`,
		"Trash":   `\Trash`,
	}
	for name, wantAttr := range want {
		if got[name] != wantAttr {
			t.Errorf("default mailbox %q: special_use = %q, want %q", name, got[name], wantAttr)
		}
	}
}

// TestGetPersonalMailboxNameBySpecialUse: the lookup behind the default Sieve
// script's spam filing (issue #987) finds the \Junk mailbox under its current name
// after a RENAME, and only in the personal namespace (RFC 8579 §4).
func TestGetPersonalMailboxNameBySpecialUse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()

	email := fmt.Sprintf("test-personal-specialuse-%d@example.com", time.Now().UnixNano())
	accountID := createTestAccount(t, db, email, "password")

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateDefaultMailboxes(ctx, tx, accountID))
	require.NoError(t, tx.Commit(ctx))

	name, err := db.GetPersonalMailboxNameBySpecialUse(ctx, accountID, `\Junk`)
	require.NoError(t, err)
	require.Equal(t, "Junk", name)

	junk, err := db.GetMailboxByName(ctx, accountID, "Junk")
	require.NoError(t, err)
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.RenameMailbox(ctx, tx, junk.ID, accountID, "Spam", nil))
	require.NoError(t, tx.Commit(ctx))

	name, err = db.GetPersonalMailboxNameBySpecialUse(ctx, accountID, `\Junk`)
	require.NoError(t, err)
	require.Equal(t, "Spam", name, "the attribute follows the mailbox through RENAME")

	_, err = db.GetPersonalMailboxNameBySpecialUse(ctx, accountID, `\All`)
	require.ErrorIs(t, err, consts.ErrMailboxNotFound, "no mailbox carries the attribute")

	_, err = db.GetWritePool().Exec(ctx, `UPDATE mailboxes SET is_shared = TRUE WHERE id = $1`, junk.ID)
	require.NoError(t, err)
	_, err = db.GetPersonalMailboxNameBySpecialUse(ctx, accountID, `\Junk`)
	require.ErrorIs(t, err, consts.ErrMailboxNotFound, "a mailbox in the shared namespace is not in the personal one")
}
