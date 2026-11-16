package db

import (
	"context"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
)

func TestDeleteMailboxForUserProtectsResolvedInbox(t *testing.T) {
	ctx := context.Background()
	d, accountID := setupMailboxTestDatabase(t)
	defer d.Close()

	tx, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	require.NoError(t, d.CreateDefaultMailboxes(ctx, tx, accountID))
	require.NoError(t, tx.Commit(ctx))

	for _, name := range []string{"INBOX", "inbox", "InBoX"} {
		err := d.DeleteMailboxForUser(ctx, accountID, name)
		require.ErrorIs(t, err, consts.ErrNotPermitted, "DeleteMailboxForUser(%q) must return ErrNotPermitted", name)

		inbox, getErr := d.GetMailboxByName(ctx, accountID, "INBOX")
		require.NoError(t, getErr)
		require.Equal(t, "INBOX", inbox.Name)
	}

	var iDotMatchesInbox bool
	err = d.GetWritePool().QueryRow(ctx, "SELECT LOWER($1) = LOWER($2)", "\u0130NBOX", "INBOX").Scan(&iDotMatchesInbox)
	require.NoError(t, err)

	if iDotMatchesInbox {
		// Under libc UTF-8 collations (e.g. en_US.UTF-8), LOWER('İNBOX') = 'inbox',
		// so GetMailboxByName resolves "İNBOX" to the account's canonical INBOX while
		// Go's strings.EqualFold("İNBOX", "INBOX") is false.
		err := d.DeleteMailboxForUser(ctx, accountID, "\u0130NBOX")
		require.ErrorIs(t, err, consts.ErrNotPermitted, "DeleteMailboxForUser(\"\\u0130NBOX\") must refuse deleting resolved INBOX")

		inbox, getErr := d.GetMailboxByName(ctx, accountID, "INBOX")
		require.NoError(t, getErr)
		require.Equal(t, "INBOX", inbox.Name)
	} else {
		// Under ICU collations, LOWER('İNBOX') = 'i\u0307nbox' != 'inbox', so "İNBOX"
		// is an ordinary distinct mailbox rather than INBOX.
		err := d.DeleteMailboxForUser(ctx, accountID, "\u0130NBOX")
		require.ErrorIs(t, err, consts.ErrMailboxNotFound)

		require.NoError(t, d.CreateMailboxForUser(ctx, accountID, "\u0130NBOX"))
		require.NoError(t, d.DeleteMailboxForUser(ctx, accountID, "\u0130NBOX"))

		_, err = d.GetMailboxByName(ctx, accountID, "\u0130NBOX")
		require.ErrorIs(t, err, consts.ErrMailboxNotFound)

		inbox, getErr := d.GetMailboxByName(ctx, accountID, "INBOX")
		require.NoError(t, getErr)
		require.Equal(t, "INBOX", inbox.Name)
	}
}
