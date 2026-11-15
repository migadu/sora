package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
)

func TestRenameMailboxRefusesInbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()

	ctx := context.Background()
	email := fmt.Sprintf("rename_inbox_%d@example.com", time.Now().UnixNano())

	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	accountID, err := database.CreateAccount(ctx, tx, CreateAccountRequest{
		Email:     email,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, database.CreateDefaultMailboxes(ctx, tx, accountID))
	require.NoError(t, tx.Commit(ctx))

	inbox, err := database.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	require.Equal(t, "INBOX", inbox.Name)

	for _, target := range []string{"MovedInbox", "inbox", "Trash"} {
		t.Run(target, func(t *testing.T) {
			txRename, err := database.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer txRename.Rollback(ctx)

			err = database.RenameMailbox(ctx, txRename, inbox.ID, accountID, target, nil)
			require.ErrorIs(t, err, consts.ErrNotPermitted, "RenameMailbox on INBOX to %q must be refused with ErrNotPermitted", target)
		})
	}

	inboxAfter, err := database.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	require.Equal(t, inbox.ID, inboxAfter.ID)
	require.Equal(t, "INBOX", inboxAfter.Name)
}
