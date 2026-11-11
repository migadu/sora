//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// sharedMailboxOwners returns the owners of the live shared mailboxes called name.
func sharedMailboxOwners(t *testing.T, server *common.TestServer, name string) []int64 {
	t.Helper()
	rows, err := server.ResilientDB.QueryWithRetry(context.Background(),
		"SELECT account_id FROM mailboxes WHERE LOWER(name) = LOWER($1) AND is_shared = TRUE AND deleted_at IS NULL ORDER BY id", name)
	require.NoError(t, err)
	defer rows.Close()
	var owners []int64
	for rows.Next() {
		var id int64
		require.NoError(t, rows.Scan(&id))
		owners = append(owners, id)
	}
	require.NoError(t, rows.Err())
	return owners
}

// mailboxesUnder counts the account's live mailboxes called prefix or below it.
func mailboxesUnder(t *testing.T, server *common.TestServer, accountID int64, prefix string) int {
	t.Helper()
	var n int
	require.NoError(t, server.ResilientDB.QueryRowWithRetry(context.Background(),
		"SELECT count(*) FROM mailboxes WHERE account_id = $1 AND LOWER(name) LIKE LOWER($2) || '%' AND deleted_at IS NULL", accountID, prefix).Scan(&n))
	return n
}

// TestSharedCreate_PersonalNamesakeDoesNotMaskSharedAncestor covers issue #249 item 1.
// CREATE looks for the shared mailbox the new one goes into, skipping personal
// mailboxes of the user's under an ancestor's name. But the lookup answers with the
// user's own mailbox of a name before any shared one, so a personal namesake hid the
// shared mailbox at that level altogether.
func TestSharedCreate_PersonalNamesakeDoesNotMaskSharedAncestor(t *testing.T) {
	for _, tc := range []struct {
		name            string
		allowUserCreate bool
		// grantOn is the mailbox, relative to the team mailbox, the member is
		// granted rights on; it is also where the member's personal namesake sits.
		grantOn string
		rights  string
	}{
		{"admin-only creation", false, "", "lrswipkxte"},
		{"user creation allowed", true, "", "lrswipkxte"},
		{"create right without lookup below the shared root", false, "/Sub", "k"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServerWithOptions(t, sharedMailboxSettings(tc.allowUserCreate, true))
			defer server.Close()
			member, memberPassword := createSecondUser(t, server, "example.com", "namesakemask")

			adminCtx := adminSharedContext("Shared/")
			ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(adminCtx, owner.Email)
			require.NoError(t, err)
			memberID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(adminCtx, member)
			require.NoError(t, err)
			team := fmt.Sprintf("Shared/Team-%d", common.GetTimestamp())
			require.NoError(t, server.ResilientDB.CreateMailboxForUserWithRetry(adminCtx, ownerID, team))

			c := loginClient(t, server, owner.Email, owner.Password)
			parent := team + tc.grantOn
			if tc.grantOn != "" {
				require.NoError(t, c.Create(parent, nil).Wait())
			}
			require.NoError(t, c.SetACL(parent, imap.RightsIdentifier(member), imap.RightModificationReplace, imap.RightSet(tc.rights)).Wait())

			// The member's personal mailbox of the same name (User API, Sieve
			// fileinto :create, or made while shared mailboxes were off).
			require.NoError(t, server.ResilientDB.CreateMailboxWithRetry(context.Background(), memberID, parent, nil))

			cm := loginClient(t, server, member, memberPassword)
			child := parent + "/Child"
			require.NoError(t, cm.Create(child, nil).Wait(), "CREATE inside a shared mailbox the member holds 'k' on")

			require.Equal(t, []int64{ownerID}, sharedMailboxOwners(t, server, child), "the new mailbox belongs to the shared mailbox's owner")
			var memberShared int
			require.NoError(t, server.ResilientDB.QueryRowWithRetry(adminCtx,
				"SELECT count(*) FROM mailboxes WHERE account_id = $1 AND is_shared = TRUE AND deleted_at IS NULL", memberID).Scan(&memberShared))
			require.Zero(t, memberShared, "CREATE made shared mailboxes of the member's own")
		})
	}
}

// TestSharedCreate_MissingParentsAreTheOwners covers issue #249 item 2. The parents
// CREATE creates on the way to a new mailbox are the hierarchy owner's. They were
// looked up as the owner sees names, which finds another owner's shared mailbox of
// a missing parent's name: the acting user was then checked against that mailbox.
func TestSharedCreate_MissingParentsAreTheOwners(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	member, memberPassword := createSecondUser(t, server, "example.com", "parentmember")
	other, otherPassword := createSecondUser(t, server, "example.com", "parentother")

	adminCtx := adminSharedContext("Shared/")
	ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(adminCtx, owner.Email)
	require.NoError(t, err)
	otherID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(adminCtx, other)
	require.NoError(t, err)

	team := fmt.Sprintf("Shared/Team-%d", common.GetTimestamp())
	c := loginClient(t, server, owner.Email, owner.Password)
	require.NoError(t, c.Create(team, nil).Wait())
	require.NoError(t, c.SetACL(team, imap.RightsIdentifier(member), imap.RightModificationReplace, imap.RightSet("lrswipkxte")).Wait())

	// Another owner's shared mailbox under the name of a parent the owner lacks,
	// visible to the owner but not to the member.
	sub := team + "/Sub"
	require.NoError(t, server.ResilientDB.CreateMailboxWithRetry(adminCtx, otherID, sub, nil))
	co := loginClient(t, server, other, otherPassword)
	require.NoError(t, co.SetACL(sub, imap.RightsIdentifier(owner.Email), imap.RightModificationReplace, imap.RightSet("lrs")).Wait())

	cm := loginClient(t, server, member, memberPassword)
	leaf := sub + "/Mid/Leaf"
	require.NoError(t, cm.Create(leaf, nil).Wait(), "CREATE below a shared mailbox the member holds 'k' on")

	for _, name := range []string{sub + "/Mid", leaf} {
		require.Equal(t, []int64{ownerID}, sharedMailboxOwners(t, server, name), "%s belongs to the shared mailbox's owner", name)
	}
	require.ElementsMatch(t, []int64{ownerID, otherID}, sharedMailboxOwners(t, server, sub), "the missing parent is created for the owner, beside the other owner's")
	require.Equal(t, 1, mailboxesUnder(t, server, otherID, sub), "nothing is created in the other owner's mailbox")
}

// TestCreate_ReadsParentsItCreatedFromMaster covers issue #249 item 2. CREATE writes
// a missing parent to the master and reads it straight back. In a session that had
// not written before, that read went to a replica, which may not have the parent
// yet. The replica here is one that lags: it has the mailboxes as they were before
// the command.
func TestCreate_ReadsParentsItCreatedFromMaster(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	defer installLaggingReplica(t, server, nil, []string{"mailboxes"}, false)()

	name := fmt.Sprintf("PinTop-%d/Mid/Leaf", common.GetTimestamp())
	_, tagged := c.read(c.send("CREATE "+name), "CREATE")
	require.Contains(t, tagged, " OK", "CREATE must read the parents it has just created from the master, got: %s", tagged)
}

// TestSharedRename_ForeignParentOwnerCannotLookUp covers issue #249 item 3. RENAME
// refuses to move a mailbox into another owner's shared mailbox, and looked for one
// with a lookup that needs the 'l' right. The check for allow_user_create accepts
// one the owner merely holds 'k' on. So with 'k' and no 'l', neither refused, and
// the "missing" parents were created: a top-level shared mailbox of the owner's
// own, under the other owner's name, whatever allow_user_create says.
func TestSharedRename_ForeignParentOwnerCannotLookUp(t *testing.T) {
	for _, allowUserCreate := range []bool{false, true} {
		t.Run(fmt.Sprintf("allow_user_create=%v", allowUserCreate), func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServerWithOptions(t, sharedMailboxSettings(allowUserCreate, true))
			defer server.Close()
			other, otherPassword := createSecondUser(t, server, "example.com", "hiddenparent")

			adminCtx := adminSharedContext("Shared/")
			ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(adminCtx, owner.Email)
			require.NoError(t, err)
			otherID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(adminCtx, other)
			require.NoError(t, err)
			ts := common.GetTimestamp()
			mine := fmt.Sprintf("Shared/Mine-%d", ts)
			theirs := fmt.Sprintf("Shared/Theirs-%d", ts)
			require.NoError(t, server.ResilientDB.CreateMailboxForUserWithRetry(adminCtx, ownerID, mine))
			require.NoError(t, server.ResilientDB.CreateMailboxForUserWithRetry(adminCtx, otherID, theirs))

			c := loginClient(t, server, owner.Email, owner.Password)
			require.NoError(t, c.Create(mine+"/Box", nil).Wait())
			co := loginClient(t, server, other, otherPassword)
			require.NoError(t, co.SetACL(theirs, imap.RightsIdentifier(owner.Email), imap.RightModificationReplace, imap.RightSet("rswipkxtea")).Wait())

			for _, to := range []string{theirs + "/Box", theirs + "/New/Box"} {
				requireResponseCode(t, c.Rename(mine+"/Box", to, nil).Wait(), imap.ResponseCodeCannot, "RENAME into another owner's shared mailbox: "+to)
			}
			require.Equal(t, []int64{ownerID}, sharedMailboxOwners(t, server, mine+"/Box"), "the mailbox stays where it was")
			require.Zero(t, mailboxesUnder(t, server, ownerID, theirs), "the refused RENAME created mailboxes for the owner under the other owner's name")
			require.Equal(t, 1, mailboxesUnder(t, server, otherID, theirs), "nothing is created in the other owner's mailbox")
		})
	}
}

// TestSharedRename_ForeignParentOfTheActingUser covers issue #249 item 3. A user
// with rights on a shared mailbox may rename it, and it stays its owner's. The new
// parent was looked for only as the owner sees names: a shared mailbox of the acting
// user's own, which the owner cannot see, was not found, and a namesake hierarchy
// was created for the owner in front of it.
func TestSharedRename_ForeignParentOfTheActingUser(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	other, otherPassword := createSecondUser(t, server, "example.com", "delegate")

	ctx := context.Background()
	ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(ctx, owner.Email)
	require.NoError(t, err)
	ts := common.GetTimestamp()
	mine := fmt.Sprintf("Shared/Mine-%d", ts)
	theirs := fmt.Sprintf("Shared/Theirs-%d", ts)
	// The owner's shared mailbox is stored flat, as an administrator's import may
	// leave it: the owner has no mailbox above it.
	require.NoError(t, server.ResilientDB.CreateMailboxWithRetry(adminSharedContext("Shared/"), ownerID, mine+"/Box", nil))
	c := loginClient(t, server, owner.Email, owner.Password)
	require.NoError(t, c.SetACL(mine+"/Box", imap.RightsIdentifier(other), imap.RightModificationReplace, imap.RightSet("lrswipkxtea")).Wait())
	co := loginClient(t, server, other, otherPassword)
	require.NoError(t, co.Create(theirs, nil).Wait())

	for _, to := range []string{theirs + "/Box", theirs + "/New/Box"} {
		requireResponseCode(t, co.Rename(mine+"/Box", to, nil).Wait(), imap.ResponseCodeCannot, "RENAME into the acting user's own shared mailbox: "+to)
	}
	require.Equal(t, []int64{ownerID}, sharedMailboxOwners(t, server, mine+"/Box"), "the mailbox stays where it was")
	require.Zero(t, mailboxesUnder(t, server, ownerID, theirs), "the refused RENAME created mailboxes for the owner under the acting user's name")
}

// TestSharedRename_ForeignParentRefusedBeforeCreateRight covers issue #249 item 3.
// A move into another owner's shared mailbox can never succeed, whatever rights the
// user holds there. The 'k' right on it was checked first, so a user without it was
// told NO [NOPERM], as if being granted 'k' would help.
func TestSharedRename_ForeignParentRefusedBeforeCreateRight(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	other, otherPassword := createSecondUser(t, server, "example.com", "nocreateright")

	ts := common.GetTimestamp()
	mine := fmt.Sprintf("Shared/Mine-%d", ts)
	theirs := fmt.Sprintf("Shared/Theirs-%d", ts)
	c := loginClient(t, server, owner.Email, owner.Password)
	require.NoError(t, c.Create(mine+"/Box", nil).Wait())
	co := loginClient(t, server, other, otherPassword)
	require.NoError(t, co.Create(theirs, nil).Wait())
	require.NoError(t, co.SetACL(theirs, imap.RightsIdentifier(owner.Email), imap.RightModificationReplace, imap.RightSet("lrswip")).Wait())

	for _, to := range []string{theirs + "/Box", theirs + "/New/Box"} {
		requireResponseCode(t, c.Rename(mine+"/Box", to, nil).Wait(), imap.ResponseCodeCannot, "RENAME into another owner's shared mailbox: "+to)
	}
}
