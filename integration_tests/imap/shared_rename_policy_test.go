//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adminSharedContext is the context an administrator creates shared mailboxes with
// (sora-admin mailbox create): the shared settings, allowed to create shared roots.
func adminSharedContext(prefix string) context.Context {
	return context.WithValue(context.Background(), consts.ConfigContextKey, &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: prefix, AllowUserCreate: true, DefaultRights: "lrswipkxtea"},
	})
}

func loginClient(t *testing.T, server *common.TestServer, email, password string) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	t.Cleanup(func() { c.Logout() })
	require.NoError(t, c.Login(email, password).Wait())
	return c
}

// TestSharedRename_CannotMintTopLevelSharedMailbox covers issue #231 item 1. With
// allow_user_create false a user can't create a top-level shared mailbox, but could
// CREATE a child of an administrator's one and RENAME it to the top level: the
// namespace root already exists, so no parent was created and nothing asked.
func TestSharedRename_CannotMintTopLevelSharedMailbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServerWithOptions(t, sharedMailboxSettings(false, true))
	defer server.Close()

	adminCtx := adminSharedContext("Shared/")
	ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(adminCtx, owner.Email)
	require.NoError(t, err)
	ts := common.GetTimestamp()
	team := fmt.Sprintf("Shared/Team-%d", ts)
	require.NoError(t, server.ResilientDB.CreateMailboxForUserWithRetry(adminCtx, ownerID, team))

	c := loginClient(t, server, owner.Email, owner.Password)
	temp := team + "/Temp"
	require.NoError(t, c.Create(temp, nil).Wait(), "CREATE inside an existing shared mailbox")

	newRoot := fmt.Sprintf("Shared/NewRoot-%d", ts)
	requireResponseCode(t, c.Rename(temp, newRoot, nil).Wait(), imap.ResponseCodeNoPerm, "RENAME of a child to a new top-level shared mailbox")
	names := mailboxNames(t, c)
	require.Contains(t, names, temp)
	require.NotContains(t, names, newRoot)

	// Moving it elsewhere inside an existing shared mailbox creates no shared root.
	require.NoError(t, c.Create(team+"/Sub", nil).Wait())
	require.NoError(t, c.Rename(temp, team+"/Sub/Temp", nil).Wait())
}

// TestSharedRename_PersonalNamesake covers issue #231 item 2. A personal mailbox
// under the shared prefix (User API, Sieve fileinto :create, or made while shared
// mailboxes were off) could not be renamed at all: the IMAP layer compared names and
// required the new name inside the namespace, the database compared the stored flag
// and required it outside. And a RENAME the database then refused had already
// created and committed the new name's parents.
func TestSharedRename_PersonalNamesake(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServerWithOptions(t, sharedMailboxSettings(false, true))
	defer server.Close()

	adminCtx := adminSharedContext("Shared/")
	ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(adminCtx, owner.Email)
	require.NoError(t, err)
	ts := common.GetTimestamp()
	team := fmt.Sprintf("Shared/Team-%d", ts)
	require.NoError(t, server.ResilientDB.CreateMailboxForUserWithRetry(adminCtx, ownerID, team))
	planted := fmt.Sprintf("Shared/Planted-%d", ts)
	require.NoError(t, server.ResilientDB.CreateMailboxForUserWithRetry(context.Background(), ownerID, planted))

	c := loginClient(t, server, owner.Email, owner.Password)

	leaked := team + "/LeakedParent"
	requireResponseCode(t, c.Rename(planted, leaked+"/Planted", nil).Wait(), imap.ResponseCodeCannot, "RENAME of a personal mailbox into a shared one")
	names := mailboxNames(t, c)
	require.Contains(t, names, planted)
	assert.NotContains(t, names, leaked, "a refused RENAME left the parent it created behind")

	personal := fmt.Sprintf("PersonalPlanted-%d", ts)
	require.NoError(t, c.Rename(planted, personal, nil).Wait(), "a personal mailbox under the shared prefix can be renamed out of it")
	names = mailboxNames(t, c)
	require.Contains(t, names, personal)
	require.NotContains(t, names, planted)
}

// TestRename_IntoOwnDescendantCreatesNothing covers issue #231 item 2: RENAME of a
// mailbox to a name below itself can never succeed, yet the missing levels of the
// new name were created (under the mailbox) before the database refused the move,
// which the client was told was a server bug.
func TestRename_IntoOwnDescendantCreatesNothing(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	c := loginClient(t, server, owner.Email, owner.Password)

	ts := common.GetTimestamp()
	for _, box := range []string{fmt.Sprintf("CycleBox-%d", ts), fmt.Sprintf("Shared/CycleBox-%d", ts)} {
		require.NoError(t, c.Create(box, nil).Wait())
		requireResponseCode(t, c.Rename(box, box+"/Sub1/Sub2/CycleBox", nil).Wait(), imap.ResponseCodeCannot, "RENAME "+box+" below itself")
		names := mailboxNames(t, c)
		require.Contains(t, names, box)
		for _, name := range []string{box + "/Sub1", box + "/Sub1/Sub2"} {
			require.NotContains(t, names, name, "a refused RENAME left the parent it created behind")
		}
	}
}

// TestSharedRename_IntoAnotherOwnersMailbox covers issue #231 item 3. The new
// parent was looked up as the owner sees it, which finds another owner's shared
// mailbox of that name; a mailbox can't be moved to another owner, so the database
// did not find that parent among the owner's and the client got NO [SERVERBUG].
func TestSharedRename_IntoAnotherOwnersMailbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	other, otherPassword := createSecondUser(t, server, "example.com", "foreignparent")

	ts := common.GetTimestamp()
	mine := fmt.Sprintf("Shared/Mine-%d", ts)
	theirs := fmt.Sprintf("Shared/Theirs-%d", ts)
	c := loginClient(t, server, owner.Email, owner.Password)
	require.NoError(t, c.Create(mine+"/Box", nil).Wait())
	co := loginClient(t, server, other, otherPassword)
	require.NoError(t, co.Create(theirs, nil).Wait())
	require.NoError(t, co.SetACL(theirs, imap.RightsIdentifier(owner.Email), imap.RightModificationReplace, imap.RightSet("lrswipkxtea")).Wait())

	for _, to := range []string{theirs + "/Box", theirs + "/New/Box"} {
		requireResponseCode(t, c.Rename(mine+"/Box", to, nil).Wait(), imap.ResponseCodeCannot, "RENAME into another owner's shared mailbox: "+to)
	}
	require.Contains(t, mailboxNames(t, c), mine+"/Box")
	require.NotContains(t, mailboxNames(t, co), theirs+"/New")

	ctx := context.Background()
	ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(ctx, owner.Email)
	require.NoError(t, err)
	var namesakes int
	require.NoError(t, server.ResilientDB.QueryRowWithRetry(ctx,
		"SELECT count(*) FROM mailboxes WHERE account_id = $1 AND LOWER(name) LIKE LOWER($2) || '%' AND deleted_at IS NULL", ownerID, theirs).Scan(&namesakes))
	require.Zero(t, namesakes, "the refused RENAME created mailboxes for the owner under the other owner's name")
}

// TestResolveOrCreateMailboxPath_OwnerScoped covers issue #231 item 3 for the helper
// sora-admin mailbox rename uses: the path it resolves or creates is the account's
// own. It returned another owner's shared mailbox of that name as the parent, which
// no create or rename for the account accepts.
func TestResolveOrCreateMailboxPath_OwnerScoped(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	other, otherPassword := createSecondUser(t, server, "example.com", "ownerscoped")

	theirs := fmt.Sprintf("Shared/Theirs-%d", common.GetTimestamp())
	co := loginClient(t, server, other, otherPassword)
	require.NoError(t, co.Create(theirs, nil).Wait())
	require.NoError(t, co.SetACL(theirs, imap.RightsIdentifier(owner.Email), imap.RightModificationReplace, imap.RightSet("lrswipkxtea")).Wait())

	adminCtx := adminSharedContext("Shared/")
	ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(adminCtx, owner.Email)
	require.NoError(t, err)
	for _, path := range []string{theirs, theirs + "/Sub"} {
		id, err := server.ResilientDB.ResolveOrCreateMailboxPathWithRetry(adminCtx, ownerID, path)
		require.NoError(t, err, path)
		var accountID int64
		require.NoError(t, server.ResilientDB.QueryRowWithRetry(adminCtx, "SELECT account_id FROM mailboxes WHERE id = $1", *id).Scan(&accountID))
		require.Equal(t, ownerID, accountID, "%s resolved to another owner's mailbox", path)
	}
}

// TestSharedCreate_UnderNonSharedParentSeedsDefaultRights covers issue #231 item 4.
// A shared mailbox takes its ACL from its parent, and default_rights only when it
// has none. Its parent need not be shared: with a prefix of several levels the
// levels above the namespace are personal, and so is a "Shared" made while shared
// mailboxes were off. Either has no ACL, and the shared mailbox got none.
func TestSharedCreate_UnderNonSharedParentSeedsDefaultRights(t *testing.T) {
	for _, tc := range []struct{ name, prefix, plant string }{
		{"multi-segment prefix", "Public/Rooms/", ""},
		{"personal namespace root", "Shared/", "Shared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{SharedMailboxes: &config.SharedMailboxesConfig{
				Enabled: true, NamespacePrefix: tc.prefix, AllowUserCreate: true, DefaultRights: "lrswipkxte",
			}})
			defer server.Close()
			ctx := context.Background()
			ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(ctx, owner.Email)
			require.NoError(t, err)
			if tc.plant != "" {
				require.NoError(t, server.ResilientDB.CreateMailboxWithRetry(ctx, ownerID, tc.plant, nil))
			}

			c := loginClient(t, server, owner.Email, owner.Password)
			name := fmt.Sprintf("%sTeam-%d", tc.prefix, common.GetTimestamp())
			require.NoError(t, c.Create(name, nil).Wait())

			for _, mailbox := range []string{name, name + "/Child"} {
				if mailbox != name {
					require.NoError(t, c.Create(mailbox, nil).Wait())
				}
				var rights []string
				rows, err := server.ResilientDB.QueryWithRetry(ctx, `
					SELECT acl.rights FROM mailbox_acls acl JOIN mailboxes m ON m.id = acl.mailbox_id
					WHERE m.account_id = $1 AND m.name = $2 AND m.deleted_at IS NULL AND acl.account_id = $1`, ownerID, mailbox)
				require.NoError(t, err)
				for rows.Next() {
					var r string
					require.NoError(t, rows.Scan(&r))
					rights = append(rights, r)
				}
				rows.Close()
				require.NoError(t, rows.Err())
				require.Equal(t, []string{"lrswipkxte"}, rights, "%s must carry the creator's default_rights", mailbox)
			}
		})
	}
}

// TestSharedCreate_OwnerIsNearestSharedAncestor covers issue #231 item 4. CREATE
// inside another owner's shared mailbox creates in that owner's hierarchy. The
// owner was taken from the nearest existing parent, shared or not, while the
// allow_user_create check looks past personal namesakes: a personal mailbox of the
// user's under that name made the new mailbox a shared one of the user's own.
func TestSharedCreate_OwnerIsNearestSharedAncestor(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServerWithOptions(t, sharedMailboxSettings(false, true))
	defer server.Close()
	member, memberPassword := createSecondUser(t, server, "example.com", "nearestshared")

	adminCtx := adminSharedContext("Shared/")
	ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(adminCtx, owner.Email)
	require.NoError(t, err)
	memberID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(adminCtx, member)
	require.NoError(t, err)
	team := fmt.Sprintf("Shared/Team-%d", common.GetTimestamp())
	require.NoError(t, server.ResilientDB.CreateMailboxForUserWithRetry(adminCtx, ownerID, team))
	c := loginClient(t, server, owner.Email, owner.Password)
	require.NoError(t, c.SetACL(team, imap.RightsIdentifier(member), imap.RightModificationReplace, imap.RightSet("lrswipkxte")).Wait())

	// A personal mailbox of the member's under the shared mailbox's name, stored
	// flat as the User API created them before it linked parents.
	require.NoError(t, server.ResilientDB.CreateMailboxWithRetry(context.Background(), memberID, team+"/Sub", nil))

	cm := loginClient(t, server, member, memberPassword)
	leaf := team + "/Sub/Leaf"
	require.NoError(t, cm.Create(leaf, nil).Wait())

	var memberShared int
	require.NoError(t, server.ResilientDB.QueryRowWithRetry(adminCtx,
		"SELECT count(*) FROM mailboxes WHERE account_id = $1 AND is_shared = TRUE AND deleted_at IS NULL", memberID).Scan(&memberShared))
	require.Zero(t, memberShared, "allow_user_create is off, yet CREATE made shared mailboxes of the member's own")
	created, err := server.ResilientDB.GetMailboxByNameWithRetry(adminCtx, ownerID, leaf)
	require.NoError(t, err, "the new mailbox belongs to the shared mailbox's owner")
	require.Equal(t, ownerID, created.AccountID)
}
