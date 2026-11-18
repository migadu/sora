package db

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
)

// With [shared_mailboxes] enabled = false (SetSharedMailboxAccess(false)), a grant
// to another user or to "anyone" counts for nothing in any lookup or right check,
// and the owner keeps every mailbox, its shared ones included. Turning access back
// on restores the grants, which were never touched.
func TestSharedMailboxAccessOff(t *testing.T) {
	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.WithValue(context.Background(), consts.ConfigContextKey, &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/", AllowAnyoneIdentifier: true},
	})
	domain := fmt.Sprintf("sharedoff-%d.example.com", time.Now().UnixNano())
	account := func(local string) (int64, string) {
		t.Helper()
		email := local + "@" + domain
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		id, err := database.CreateAccount(ctx, tx, CreateAccountRequest{Email: email, Password: "password", HashType: "bcrypt", IsPrimary: true})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return id, email
	}
	owner, _ := account("owner")
	grantee, granteeEmail := account("grantee")
	create := func(name string) *DBMailbox {
		t.Helper()
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, database.CreateMailbox(ctx, tx, owner, name, nil))
		require.NoError(t, tx.Commit(ctx))
		mailbox, err := database.GetMailboxByName(ctx, owner, name)
		require.NoError(t, err)
		return mailbox
	}
	direct := create("Shared/Direct")
	public := create("Shared/Public")
	const granted = "lrswitea"
	require.NoError(t, database.SetMailboxACL(ctx, direct.ID, 0, granteeEmail, ACLReplace, granted))
	require.NoError(t, database.SetMailboxACL(ctx, public.ID, 0, "anyone", ACLReplace, granted))

	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	insertTestMessageWithUIDForPoll(t, database, ctx, tx, owner, direct.ID, direct.Name, 1, nil)
	require.NoError(t, tx.Commit(ctx))
	var messageID int64
	require.NoError(t, database.GetWritePool().QueryRow(ctx,
		`SELECT id FROM messages WHERE mailbox_id = $1 AND uid = 1`, direct.ID).Scan(&messageID))

	listed := func(t *testing.T, accountID int64) []int64 {
		t.Helper()
		mailboxes, err := database.GetMailboxes(ctx, accountID, false)
		require.NoError(t, err)
		var ids []int64
		for _, m := range mailboxes {
			ids = append(ids, m.ID)
		}
		return ids
	}
	notified := func(t *testing.T, accountID int64) []int64 {
		t.Helper()
		mailboxes, err := database.GetMailboxNotifySnapshot(ctx, accountID)
		require.NoError(t, err)
		var ids []int64
		for _, m := range mailboxes {
			ids = append(ids, m.ID)
		}
		return ids
	}
	subscribe := func(t *testing.T, accountID int64, name string) *NotifyMailbox {
		t.Helper()
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		state, err := database.UpdateSubscriptionReturningState(ctx, tx, accountID, name, true)
		require.NoError(t, err)
		return &state.Mailbox
	}

	exists, err := database.HasForeignSharedGrants(ctx)
	require.NoError(t, err)
	require.True(t, exists)

	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%v", enabled), func(t *testing.T) {
			database.SetSharedMailboxAccess(enabled)

			// The owner sees and holds its shared mailboxes either way.
			require.Subset(t, listed(t, owner), []int64{direct.ID, public.ID})
			require.Subset(t, notified(t, owner), []int64{direct.ID, public.ID})
			for _, m := range []*DBMailbox{direct, public} {
				got, err := database.GetMailboxByName(ctx, owner, m.Name)
				require.NoError(t, err)
				require.Equal(t, m.ID, got.ID)
				got, err = database.GetSharedMailboxByNameForRight(ctx, owner, m.Name, ACLRightRead)
				require.NoError(t, err)
				require.Equal(t, m.ID, got.ID)
				ok, err := database.CheckMailboxPermission(ctx, m.ID, owner, ACLRightAdmin)
				require.NoError(t, err)
				require.True(t, ok)
				rights, err := database.GetUserMailboxRights(ctx, m.ID, owner)
				require.NoError(t, err)
				require.Equal(t, AllACLRights, rights)
			}
			_, err := database.GetMessageByID(ctx, owner, messageID)
			require.NoError(t, err)

			// The grantee reaches them only while access is on.
			for _, m := range []*DBMailbox{direct, public} {
				require.Equal(t, enabled, slices.Contains(listed(t, grantee), m.ID), "LIST %s", m.Name)
				require.Equal(t, enabled, slices.Contains(notified(t, grantee), m.ID), "NOTIFY %s", m.Name)

				got, err := database.GetMailboxByName(ctx, grantee, m.Name)
				if enabled {
					require.NoError(t, err)
					require.Equal(t, m.ID, got.ID)
				} else {
					require.ErrorIs(t, err, consts.ErrMailboxNotFound)
				}
				for _, lookup := range []func(context.Context, int64, string, ACLRight) (*DBMailbox, error){
					database.GetMailboxByNameForRight, database.GetSharedMailboxByNameForRight,
				} {
					got, err := lookup(ctx, grantee, m.Name, ACLRightRead)
					if enabled {
						require.NoError(t, err)
						require.Equal(t, m.ID, got.ID)
					} else {
						require.ErrorIs(t, err, consts.ErrMailboxNotFound)
					}
				}

				ok, err := database.CheckMailboxPermission(ctx, m.ID, grantee, ACLRightRead)
				require.NoError(t, err)
				require.Equal(t, enabled, ok, "right r on %s", m.Name)
				ins, del, exp, err := database.CheckMoveRights(ctx, m.ID, m.ID, grantee)
				require.NoError(t, err)
				require.Equal(t, []bool{enabled, enabled, enabled}, []bool{ins, del, exp})
				rights, err := database.GetUserMailboxRights(ctx, m.ID, grantee)
				require.NoError(t, err)
				require.Equal(t, enabled, rights != "", "MYRIGHTS %s = %q", m.Name, rights)

				state := subscribe(t, grantee, m.Name)
				require.Equal(t, enabled, state.ID == m.ID, "subscription target %s", m.Name)
			}

			_, err = database.GetMessageByID(ctx, grantee, messageID)
			err2 := database.UpdateMessageFlags(ctx, grantee, messageID, []string{`\Flagged`}, nil)
			if enabled {
				require.NoError(t, err)
				require.NoError(t, err2)
			} else {
				require.ErrorIs(t, err, consts.ErrDBNotFound)
				require.ErrorIs(t, err2, consts.ErrDBNotFound)
			}

			// Adding to its own entry takes the admin right the grantee holds, which
			// counts only while access is on. An administrative change (grantor 0)
			// works either way, so an operator can still revoke.
			err = database.SetMailboxACL(ctx, direct.ID, grantee, granteeEmail, ACLAdd, "k")
			if enabled {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, consts.ErrNotPermitted)
			}
			require.NoError(t, database.SetMailboxACL(ctx, direct.ID, 0, granteeEmail, ACLReplace, granted))
		})
	}
}
