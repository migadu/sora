package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRenameMailbox_DescendantNamesByLevel is issue #1650. A rename gave each
// descendant the new name followed by its own name after as many characters as the
// renamed mailbox's name has. A descendant is linked below its parent by LOWER(name),
// and under an ICU collation lower() takes two spellings of different length for one
// name: lower('İ') is "i̇" (i + U+0307), so "İq" and "i̇q" are one mailbox, and a child
// created as "i̇q/c" below "İq" became "Y//c" on a rename to "Y". The child update, its
// conflict check, RenameCrossesSharedBoundary and RenameSubscriptions all cut names
// that way. A libc collation lowers one code point to one, so under it no two spellings
// of one name differ in length and the test is skipped.
func TestRenameMailbox_DescendantNamesByLevel(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	const iDot = "i\u0307" // i + U+0307 COMBINING DOT ABOVE, ICU's lower('İ')
	var same bool
	require.NoError(t, db.GetWritePool().QueryRow(ctx,
		`SELECT LOWER($1::text) = LOWER($2::text)`, "\u0130q", iDot+"q").Scan(&same))
	if !same {
		t.Skipf("the database keeps %q and %q apart: no two spellings of one name differ in length", "\u0130q", iDot+"q")
	}

	newAccount := func(t *testing.T) int64 {
		t.Helper()
		return createTestAccount(t, db, fmt.Sprintf("rename-levels-%d@example.com", time.Now().UnixNano()), "password123")
	}
	inTx := func(t *testing.T, fn func(tx pgx.Tx) error) error {
		t.Helper()
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	// rename renames oldName to the top-level newName, as IMAP RENAME does.
	rename := func(t *testing.T, ctx context.Context, accountID int64, oldName, newName string) error {
		t.Helper()
		mbox, err := db.GetMailboxByName(ctx, accountID, oldName)
		require.NoError(t, err)
		return inTx(t, func(tx pgx.Tx) error { return db.RenameMailbox(ctx, tx, mbox.ID, accountID, newName, nil) })
	}
	mailboxNames := func(t *testing.T, accountID int64) []string {
		t.Helper()
		rows, err := db.GetWritePool().Query(ctx,
			`SELECT name FROM mailboxes WHERE account_id = $1 AND deleted_at IS NULL`, accountID)
		require.NoError(t, err)
		names, err := pgx.CollectRows(rows, pgx.RowTo[string])
		require.NoError(t, err)
		return names
	}

	t.Run("descendants spelled longer than the mailbox", func(t *testing.T) {
		accountID := newAccount(t)
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "\u0130q"))
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, iDot+"q/c"))
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, iDot+"q/c/d"))
		for _, name := range []string{iDot + "q", iDot + "q/c"} {
			require.NoError(t, inTx(t, func(tx pgx.Tx) error { return db.Subscribe(ctx, tx, accountID, name) }))
		}

		require.NoError(t, rename(t, ctx, accountID, "\u0130q", "Y"))
		assert.ElementsMatch(t, []string{"Y", "Y/c", "Y/c/d"}, mailboxNames(t, accountID))
		assert.ElementsMatch(t, []string{"Y", "Y/c"}, subNames(t, db, ctx, accountID))
	})

	t.Run("descendants spelled shorter than the mailbox", func(t *testing.T) {
		accountID := newAccount(t)
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, iDot+"r"))
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "\u0130r/c"))
		require.NoError(t, inTx(t, func(tx pgx.Tx) error { return db.Subscribe(ctx, tx, accountID, "\u0130r/c") }))

		require.NoError(t, rename(t, ctx, accountID, iDot+"r", "Y"))
		assert.ElementsMatch(t, []string{"Y", "Y/c"}, mailboxNames(t, accountID))
		assert.ElementsMatch(t, []string{"Y/c"}, subNames(t, db, ctx, accountID))
	})

	t.Run("a descendant's new name is taken", func(t *testing.T) {
		accountID := newAccount(t)
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "\u0130s"))
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, iDot+"s/c"))
		// "Y/c" with no mailbox "Y", so the rename to "Y" gets past the check of the
		// mailbox's own new name.
		require.NoError(t, inTx(t, func(tx pgx.Tx) error { return db.CreateMailbox(ctx, tx, accountID, "Y/c", nil) }))

		err := rename(t, ctx, accountID, "\u0130s", "Y")
		require.ErrorContains(t, err, "conflicting mailbox names")
		require.ErrorIs(t, err, consts.ErrMailboxAlreadyExists)
		require.ElementsMatch(t, []string{"\u0130s", iDot + "s/c", "Y/c"}, mailboxNames(t, accountID))
	})

	t.Run("a descendant crosses the shared namespace boundary", func(t *testing.T) {
		cfg := &config.Config{SharedMailboxes: config.SharedMailboxesConfig{
			Enabled: true, NamespacePrefix: "Team/Shared/", AllowUserCreate: true,
		}}
		ctx := context.WithValue(ctx, consts.ConfigContextKey, cfg)
		accountID := newAccount(t)
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "\u0130t"))
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, iDot+"t/Shared"))

		// "Team" is outside the namespace, but the personal "i̇t/Shared" would become
		// its root "Team/Shared".
		mbox, err := db.GetMailboxByName(ctx, accountID, "\u0130t")
		require.NoError(t, err)
		crosses, err := db.RenameCrossesSharedBoundary(ctx, cfg.SharedMailboxes, mbox, "Team")
		require.NoError(t, err)
		assert.True(t, crosses, "RenameCrossesSharedBoundary(%q -> %q)", "\u0130t", "Team")

		require.ErrorIs(t, rename(t, ctx, accountID, "\u0130t", "Team"), consts.ErrMailboxSharedBoundary)
		require.ElementsMatch(t, []string{"\u0130t", iDot + "t/Shared"}, mailboxNames(t, accountID))
	})
}

// TestRenameMailbox_ChildConflictCaseAndSubtree is issue #1722: RenameMailbox must
// check descendant collisions with LOWER() outside the subtree being renamed and wrap
// consts.ErrMailboxAlreadyExists, and case-only or ancestor-shortening renames must
// preserve the moved subtree's subscriptions.
func TestRenameMailbox_ChildConflictCaseAndSubtree(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	newAccount := func(t *testing.T) int64 {
		t.Helper()
		return createTestAccount(t, db, fmt.Sprintf("rename-child-conflict-%d@example.com", time.Now().UnixNano()), "password123")
	}
	inTx := func(t *testing.T, fn func(tx pgx.Tx) error) error {
		t.Helper()
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	rename := func(t *testing.T, accountID int64, oldName, newName string) error {
		t.Helper()
		mbox, err := db.GetMailboxByName(ctx, accountID, oldName)
		require.NoError(t, err)
		return inTx(t, func(tx pgx.Tx) error { return db.RenameMailbox(ctx, tx, mbox.ID, accountID, newName, nil) })
	}
	mailboxNames := func(t *testing.T, accountID int64) []string {
		t.Helper()
		rows, err := db.GetWritePool().Query(ctx,
			`SELECT name FROM mailboxes WHERE account_id = $1 AND deleted_at IS NULL`, accountID)
		require.NoError(t, err)
		names, err := pgx.CollectRows(rows, pgx.RowTo[string])
		require.NoError(t, err)
		return names
	}

	t.Run("descendant conflicts case-insensitively with an existing mailbox", func(t *testing.T) {
		accountID := newAccount(t)
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "amazon"))
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "amazon/subfolder"))
		// "amazontest/SUBFOLDER" without parent "amazontest", so the rename gets past
		// the check of the target mailbox's own new name.
		require.NoError(t, inTx(t, func(tx pgx.Tx) error {
			return db.CreateMailbox(ctx, tx, accountID, "amazontest/SUBFOLDER", nil)
		}))

		amazon, err := db.GetMailboxByName(ctx, accountID, "amazon")
		require.NoError(t, err)

		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)

		err = db.RenameMailbox(ctx, tx, amazon.ID, accountID, "amazontest", nil)
		require.ErrorContains(t, err, "conflicting mailbox names")
		require.ErrorIs(t, err, consts.ErrMailboxAlreadyExists)

		// Detected before UPDATE, so the caller's transaction is not aborted by 23505.
		var one int
		require.NoError(t, tx.QueryRow(ctx, "SELECT 1").Scan(&one))
		require.NoError(t, tx.Rollback(ctx))

		require.ElementsMatch(t, []string{"amazon", "amazon/subfolder", "amazontest/SUBFOLDER"}, mailboxNames(t, accountID))
	})

	t.Run("case-only and same-name renames with children keep subscriptions", func(t *testing.T) {
		accountID := newAccount(t)
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "amazon"))
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "amazon/subfolder"))
		require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "amazon/subfolder/deep"))
		for _, name := range []string{"amazon", "amazon/subfolder"} {
			require.NoError(t, inTx(t, func(tx pgx.Tx) error { return db.Subscribe(ctx, tx, accountID, name) }))
		}

		require.NoError(t, rename(t, accountID, "amazon", "Amazon"))
		assert.ElementsMatch(t, []string{"Amazon", "Amazon/subfolder", "Amazon/subfolder/deep"}, mailboxNames(t, accountID))
		assert.Equal(t, []string{"Amazon", "Amazon/subfolder"}, subNames(t, db, ctx, accountID))

		require.NoError(t, rename(t, accountID, "Amazon", "Amazon"))
		assert.ElementsMatch(t, []string{"Amazon", "Amazon/subfolder", "Amazon/subfolder/deep"}, mailboxNames(t, accountID))
		assert.Equal(t, []string{"Amazon", "Amazon/subfolder"}, subNames(t, db, ctx, accountID))
	})

	t.Run("renaming a child mailbox to its missing ancestor's name keeps subtree subscriptions", func(t *testing.T) {
		accountID := newAccount(t)
		require.NoError(t, inTx(t, func(tx pgx.Tx) error {
			return db.CreateMailbox(ctx, tx, accountID, "Ghost/Sub", nil)
		}))
		sub, err := db.GetMailboxByName(ctx, accountID, "Ghost/Sub")
		require.NoError(t, err)
		require.NoError(t, inTx(t, func(tx pgx.Tx) error {
			return db.CreateMailbox(ctx, tx, accountID, "Ghost/Sub/Leaf", &sub.ID)
		}))
		for _, name := range []string{"Ghost/Sub/Leaf", "Ghost/Sub", "Ghost", "Ghost/Old"} {
			require.NoError(t, inTx(t, func(tx pgx.Tx) error { return db.Subscribe(ctx, tx, accountID, name) }))
		}

		require.NoError(t, rename(t, accountID, "Ghost/Sub", "Ghost"))
		assert.ElementsMatch(t, []string{"Ghost", "Ghost/Leaf"}, mailboxNames(t, accountID))
		assert.Equal(t, []string{"Ghost", "Ghost/Leaf"}, subNames(t, db, ctx, accountID))

		// Also verify when a descendant ("Pane/Sub/Sub") takes the renamed mailbox's
		// old name ("Pane/Sub"): neither the child-conflict check nor subscriptions
		// may treat the moving mailbox's old name as a conflict.
		accountID2 := newAccount(t)
		require.NoError(t, inTx(t, func(tx pgx.Tx) error {
			return db.CreateMailbox(ctx, tx, accountID2, "Pane/Sub", nil)
		}))
		paneSub, err := db.GetMailboxByName(ctx, accountID2, "Pane/Sub")
		require.NoError(t, err)
		require.NoError(t, inTx(t, func(tx pgx.Tx) error {
			return db.CreateMailbox(ctx, tx, accountID2, "Pane/Sub/Sub", &paneSub.ID)
		}))
		for _, name := range []string{"Pane/Sub/Sub", "Pane/Sub"} {
			require.NoError(t, inTx(t, func(tx pgx.Tx) error { return db.Subscribe(ctx, tx, accountID2, name) }))
		}

		require.NoError(t, rename(t, accountID2, "Pane/Sub", "Pane"))
		assert.ElementsMatch(t, []string{"Pane", "Pane/Sub"}, mailboxNames(t, accountID2))
		assert.Equal(t, []string{"Pane", "Pane/Sub"}, subNames(t, db, ctx, accountID2))
	})
}
