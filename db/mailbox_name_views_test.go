package db

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every view of the namespace must expose the same mailbox that can be addressed
// by name: owned first, then a direct ACL, then domain anyone, with oldest ID ties.
func TestMailboxViewsChooseNameLookupWinner(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.WithValue(context.Background(), consts.ConfigContextKey, &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/", AllowAnyoneIdentifier: true},
	})
	domain := fmt.Sprintf("nameviews-%d.example.com", time.Now().UnixNano())
	account := func(local, domain string) (int64, string) {
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
	viewer, email := account("viewer", domain)
	publicOwner, _ := account("public", domain)
	directOwner, _ := account("direct", domain)
	newOwner, _ := account("new", domain)
	foreignOwner, _ := account("foreign", "other-"+domain)
	create := func(owner int64, name string) *DBMailbox {
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
	public := create(publicOwner, "Shared/Dup")
	direct := create(directOwner, "Shared/dUP")
	newer := create(newOwner, "Shared/DUP")
	foreign := create(foreignOwner, "Shared/dup")
	for _, mailbox := range []*DBMailbox{public, direct, newer, foreign} {
		require.NoError(t, database.SetMailboxACL(ctx, mailbox.ID, 0, "anyone", ACLReplace, "lr"))
	}
	for _, mailbox := range []*DBMailbox{direct, newer} {
		require.NoError(t, database.SetMailboxACL(ctx, mailbox.ID, 0, email, ACLReplace, "lr"))
	}
	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, database.Subscribe(ctx, tx, viewer, "sHaReD/dUp"))
	require.NoError(t, tx.Commit(ctx))

	check := func(t *testing.T, expected *DBMailbox) {
		t.Helper()
		resolved, err := database.GetMailboxByName(ctx, viewer, "shared/dup")
		require.NoError(t, err)
		require.Equal(t, expected.ID, resolved.ID)
		for _, subscribed := range []bool{false, true} {
			rows, err := database.GetMailboxes(ctx, viewer, subscribed)
			require.NoError(t, err)
			var matching []*DBMailbox
			for _, row := range rows {
				if strings.EqualFold(row.Name, "shared/dup") {
					matching = append(matching, row)
				}
			}
			if assert.Len(t, matching, 1, "list subscribed=%v", subscribed) {
				assert.Equal(t, resolved.ID, matching[0].ID)
				assert.Equal(t, resolved.AccountID, matching[0].AccountID)
				assert.Equal(t, resolved.UIDValidity, matching[0].UIDValidity)
				assert.Equal(t, resolved.Name, matching[0].Name)
				assert.True(t, matching[0].Subscribed)
			}
		}
		snapshot, err := database.GetMailboxNotifySnapshot(ctx, viewer)
		require.NoError(t, err)
		var matching []NotifyMailbox
		for _, row := range snapshot {
			if strings.EqualFold(row.Name, "shared/dup") {
				matching = append(matching, row)
			}
		}
		if assert.Len(t, matching, 1, "notify snapshot") {
			assert.Equal(t, resolved.ID, matching[0].ID)
			assert.Equal(t, resolved.AccountID, matching[0].OwnerID)
			assert.Equal(t, resolved.UIDValidity, matching[0].UIDValidity)
			assert.Equal(t, resolved.Name, matching[0].Name)
			assert.True(t, matching[0].Subscribed)
		}
	}
	t.Run("direct-before-older-anyone-and-direct-ID-tie", func(t *testing.T) { check(t, direct) })
	require.NoError(t, database.SetMailboxACL(ctx, direct.ID, 0, email, ACLReplace, "r"))
	t.Run("no-lookup-right-skips-direct-candidate", func(t *testing.T) { check(t, newer) })
	require.NoError(t, database.SetMailboxACL(ctx, newer.ID, 0, email, ACLReplace, ""))
	t.Run("anyone-ID-tie-and-domain-isolation", func(t *testing.T) { check(t, public) })
	require.NoError(t, database.SetMailboxACL(ctx, direct.ID, 0, email, ACLReplace, "lr"))
	owned := create(viewer, "Shared/duP")
	t.Run("owned-before-direct-and-anyone", func(t *testing.T) { check(t, owned) })
	tx, err = database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, database.SoftDeleteMailbox(ctx, tx, owned.ID, viewer))
	require.NoError(t, tx.Commit(ctx))
	t.Run("deleted-owned-falls-back-to-direct", func(t *testing.T) { check(t, direct) })
}
