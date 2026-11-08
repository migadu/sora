//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// addAlias gives the account behind primary a second, non-primary address.
func addAlias(t *testing.T, server *common.TestServer, primary, alias string) {
	t.Helper()
	ctx := context.Background()
	accountID, err := server.ResilientDB.GetActiveAccountIDByAddressWithRetry(ctx, primary)
	require.NoError(t, err)
	require.NoError(t, server.ResilientDB.AddCredentialWithRetry(ctx, db.AddCredentialRequest{
		AccountID: accountID, NewEmail: alias, NewPassword: "alias-password", NewHashType: "bcrypt",
	}))
}

// entriesFor returns the GETACL entries that name the account behind any of the
// given addresses, compared case-insensitively.
func entriesFor(acl *imapclient.GetACLData, addresses ...string) map[imap.RightsIdentifier]string {
	found := map[imap.RightsIdentifier]string{}
	for id, rights := range acl.Rights {
		for _, a := range addresses {
			if strings.EqualFold(string(id), a) {
				found[id] = rights.String()
			}
		}
	}
	return found
}

func dialAndLogin(t *testing.T, address, user, password string) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialInsecure(address, nil)
	require.NoError(t, err)
	t.Cleanup(func() { c.Logout() })
	require.NoError(t, c.Login(user, password).Wait())
	return c
}

// TestACL_IdentifierSpellingsNameOneEntry: RFC 4314 §3.4 allows "multiple forms of an
// identifier to reference the same IMAP account". An address is matched without
// regard to case, and an alias names the same account, so every SETACL and DELETEACL
// must act on that account's one entry. Revoking used to match the stored text
// exactly: DELETEACL under another spelling deleted nothing, answered OK, and the user
// kept access.
func TestACL_IdentifierSpellingsNameOneEntry(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	member, memberPassword := createSecondUser(t, server, "example.com", "spelling")
	alias := fmt.Sprintf("alias-spelling-%d@example.com", common.GetTimestamp())
	addAlias(t, server, member, alias)

	co := dialAndLogin(t, server.Address, owner.Email, owner.Password)
	cm := dialAndLogin(t, server.Address, member, memberPassword)

	shared := fmt.Sprintf("Shared/Spelling-%d", common.GetTimestamp())
	require.NoError(t, co.Create(shared, nil).Wait())
	defer func() { co.Delete(shared).Wait() }()

	// requireEntry checks the owner's GETACL lists exactly one entry for the member,
	// under the member's primary address, with the given rights ("" for none).
	requireEntry := func(step, want string) {
		t.Helper()
		acl, err := co.GetACL(shared).Wait()
		require.NoError(t, err, step)
		got := entriesFor(acl, member, alias)
		if want == "" {
			require.Empty(t, got, "%s: GETACL still lists the member", step)
			return
		}
		require.Equal(t, map[imap.RightsIdentifier]string{imap.RightsIdentifier(member): want}, got, step)
	}
	// requireAccess checks what the member can actually do, not only what GETACL says.
	requireAccess := func(step string, canRead bool) {
		t.Helper()
		_, err := cm.Select(shared, nil).Wait()
		if canRead {
			require.NoError(t, err, "%s: member must be able to SELECT", step)
		} else {
			require.Error(t, err, "%s: member must no longer be able to SELECT", step)
		}
	}

	upper, upperAlias := imap.RightsIdentifier(strings.ToUpper(member)), imap.RightsIdentifier(strings.ToUpper(alias))

	require.NoError(t, co.SetACL(shared, upper, imap.RightModificationReplace, imap.RightSet("lr")).Wait())
	requireEntry("SETACL <MEMBER> lr", "lr")
	requireAccess("SETACL <MEMBER> lr", true)

	require.NoError(t, co.SetACL(shared, imap.RightsIdentifier(alias), imap.RightModificationAdd, imap.RightSet("w")).Wait())
	requireEntry("SETACL <alias> +w", "lrw")

	require.NoError(t, co.SetACL(shared, upperAlias, imap.RightModificationRemove, imap.RightSet("w")).Wait())
	requireEntry("SETACL <ALIAS> -w", "lr")

	require.NoError(t, co.DeleteACL(shared, upper).Wait())
	requireEntry("DELETEACL <MEMBER>", "")
	requireAccess("DELETEACL <MEMBER>", false)

	require.NoError(t, co.SetACL(shared, imap.RightsIdentifier(alias), imap.RightModificationReplace, imap.RightSet("lr")).Wait())
	requireEntry("SETACL <alias> lr", "lr")
	require.NoError(t, co.DeleteACL(shared, imap.RightsIdentifier(alias)).Wait())
	requireEntry("DELETEACL <alias>", "")

	// An entry written before identifiers were canonicalised, under another spelling,
	// is still the member's entry and is removed by a revoke under the primary address.
	ctx := context.Background()
	mbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, mustAccountID(t, server, owner.Email), shared)
	require.NoError(t, err)
	_, err = server.ResilientDB.GetDatabase().GetWritePool().Exec(ctx, `
		INSERT INTO mailbox_acls (mailbox_id, account_id, identifier, rights) VALUES ($1, $2, $3, 'lr')`,
		mbox.ID, mustAccountID(t, server, member), string(upperAlias))
	require.NoError(t, err)
	requireAccess("legacy <ALIAS> row", true)
	require.NoError(t, co.DeleteACL(shared, imap.RightsIdentifier(member)).Wait())
	requireEntry("DELETEACL <member> over a legacy <ALIAS> row", "")
	requireAccess("DELETEACL <member> over a legacy <ALIAS> row", false)
}

func mustAccountID(t *testing.T, server *common.TestServer, address string) int64 {
	t.Helper()
	id, err := server.ResilientDB.GetActiveAccountIDByAddressWithRetry(context.Background(), address)
	require.NoError(t, err)
	return id
}

// TestACL_ListRightsAgreesWithSetACL: LISTRIGHTS is how a client learns what SETACL
// will accept (RFC 4314 §2), so for every identifier the two must agree: a right is
// offered exactly when SETACL grants it. It used to offer everything to users in
// another domain, whom SETACL refuses, and to aliases, on which SETACL failed.
func TestACL_ListRightsAgreesWithSetACL(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	member, _ := createSecondUser(t, server, "example.com", "agree")
	alias := fmt.Sprintf("alias-agree-%d@example.com", common.GetTimestamp())
	addAlias(t, server, member, alias)
	foreign, _ := createSecondUser(t, server, "other.example.com", "agree")
	ghost := fmt.Sprintf("ghost-%d@other.example.com", common.GetTimestamp())

	co := dialAndLogin(t, server.Address, owner.Email, owner.Password)
	shared := fmt.Sprintf("Shared/Agree-%d", common.GetTimestamp())
	require.NoError(t, co.Create(shared, nil).Wait())
	defer func() { co.Delete(shared).Wait() }()

	for _, tc := range []struct {
		id        string
		grantable bool
	}{
		{member, true},
		{alias, true},
		{strings.ToUpper(member), true},
		{"anyone", true},
		{foreign, false},
		// A user in another domain that does not exist is refused the same way, so
		// neither command reveals which addresses exist outside the owner's domain.
		{ghost, false},
	} {
		id := imap.RightsIdentifier(tc.id)
		data, err := co.ListRights(shared, id).Wait()
		require.NoError(t, err, "LISTRIGHTS %s", tc.id)
		offered := strings.ContainsRune(rightGroups(data), 'l')
		require.Equal(t, tc.grantable, offered, "LISTRIGHTS %s offers l = %v (required %q, optional %q)", tc.id, offered, data.RequiredRights, rightGroups(data))

		err = co.SetACL(shared, id, imap.RightModificationReplace, imap.RightSet("l")).Wait()
		if tc.grantable {
			require.NoError(t, err, "SETACL %s l after LISTRIGHTS offered it", tc.id)
			require.NoError(t, co.DeleteACL(shared, id).Wait())
		} else {
			requireResponseCode(t, err, imap.ResponseCodeCannot, fmt.Sprintf("SETACL %s l after LISTRIGHTS offered nothing", tc.id))
		}
	}
}

func rightGroups(data *imapclient.ListRightsData) string {
	var sb strings.Builder
	for _, grp := range data.OptionalRights {
		sb.WriteString(grp.String())
	}
	return sb.String()
}

// TestACL_NoAccountOracle: every user administers their own INBOX, so if SETACL or
// LISTRIGHTS there answered differently for an existing and a missing address, any
// login could probe which accounts exist in any domain on the server. On a mailbox
// that cannot be shared, and for any address outside the owner's domain, the answer
// must not depend on whether the address exists. DELETEACL of an address that names
// no one leaves the ACL as asked and answers OK.
func TestACL_NoAccountOracle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	foreign, _ := createSecondUser(t, server, "other.example.com", "oracle")
	ghost := fmt.Sprintf("ghost-%d@other.example.com", common.GetTimestamp())
	localGhost := fmt.Sprintf("ghost-%d@example.com", common.GetTimestamp())

	co := dialAndLogin(t, server.Address, owner.Email, owner.Password)
	shared := fmt.Sprintf("Shared/Oracle-%d", common.GetTimestamp())
	require.NoError(t, co.Create(shared, nil).Wait())
	defer func() { co.Delete(shared).Wait() }()

	for _, id := range []string{foreign, ghost, localGhost} {
		ri := imap.RightsIdentifier(id)
		requireResponseCode(t, co.SetACL("INBOX", ri, imap.RightModificationReplace, imap.RightSet("lr")).Wait(),
			imap.ResponseCodeCannot, "SETACL INBOX "+id)
		data, err := co.ListRights("INBOX", ri).Wait()
		require.NoError(t, err, "LISTRIGHTS INBOX %s", id)
		require.Empty(t, data.RequiredRights.String()+rightGroups(data), "LISTRIGHTS INBOX %s", id)
		require.NoError(t, co.DeleteACL("INBOX", ri).Wait(), "DELETEACL INBOX %s", id)
	}
	for _, id := range []string{foreign, ghost} {
		requireResponseCode(t, co.SetACL(shared, imap.RightsIdentifier(id), imap.RightModificationReplace, imap.RightSet("lr")).Wait(),
			imap.ResponseCodeCannot, "SETACL "+shared+" "+id)
	}
	for _, id := range []string{foreign, ghost, localGhost} {
		require.NoError(t, co.DeleteACL(shared, imap.RightsIdentifier(id)).Wait(), "DELETEACL %s %s", shared, id)
	}
}

// TestACL_OwnerAlwaysHoldsEveryRight: the owner holds every right whatever the ACL
// says (has_mailbox_right), and LISTRIGHTS reports them all as required. So SETACL on
// the owner, even by a delegated administrator, can never take effect and is refused,
// and GETACL shows the owner with every right even when a stored row says otherwise.
func TestACL_OwnerAlwaysHoldsEveryRight(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	admin, adminPassword := createSecondUser(t, server, "example.com", "owneradmin")
	co := dialAndLogin(t, server.Address, owner.Email, owner.Password)
	shared := fmt.Sprintf("Shared/Owner-%d", common.GetTimestamp())
	require.NoError(t, co.Create(shared, nil).Wait())
	defer func() { co.Delete(shared).Wait() }()
	require.NoError(t, co.SetACL(shared, imap.RightsIdentifier(admin), imap.RightModificationReplace, imap.RightSet("lra")).Wait())
	ca := dialAndLogin(t, server.Address, admin, adminPassword)

	for name, c := range map[string]*imapclient.Client{"owner": co, "delegated admin": ca} {
		requireResponseCode(t, c.SetACL(shared, imap.RightsIdentifier(owner.Email), imap.RightModificationReplace, imap.RightSet("l")).Wait(),
			imap.ResponseCodeCannot, name+" SETACL <owner> l")
	}

	ctx := context.Background()
	tag, err := server.ResilientDB.GetDatabase().GetWritePool().Exec(ctx, `
		UPDATE mailbox_acls SET rights = 'l'
		WHERE account_id = $1 AND mailbox_id = (SELECT id FROM mailboxes WHERE account_id = $1 AND name = $2)`,
		mustAccountID(t, server, owner.Email), shared)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "a shared mailbox is created with a stored owner row")
	acl, err := co.GetACL(shared).Wait()
	require.NoError(t, err)
	require.True(t, hasAllRights(acl.Rights[imap.RightsIdentifier(owner.Email)], imap.RightSet(db.AllACLRights)),
		"GETACL shows the owner with %q", acl.Rights[imap.RightsIdentifier(owner.Email)])
}

// TestACL_RevokedAdminCannotFinishGrant: a delegated administrator's SETACL checks the
// 'a' right, then writes. If the owner revokes the administrator in between, no serial
// order of the two commands lets the administrator's grant land, so it must be
// refused. Without a second check under the ACL lock, an administrator granting
// themselves every right kept them all after the owner's revoke answered OK.
func TestACL_RevokedAdminCannotFinishGrant(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	ctx := context.Background()

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	admin, adminPassword := createSecondUser(t, server, "example.com", "revokedadmin")
	co := dialAndLogin(t, server.Address, owner.Email, owner.Password)
	shared := fmt.Sprintf("Shared/RevokedAdmin-%d", common.GetTimestamp())
	require.NoError(t, co.Create(shared, nil).Wait())
	defer func() { co.Delete(shared).Wait() }()
	require.NoError(t, co.SetACL(shared, imap.RightsIdentifier(admin), imap.RightModificationReplace, imap.RightSet("lra")).Wait())

	mbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, mustAccountID(t, server, owner.Email), shared)
	require.NoError(t, err)
	gate := &aclPermissionGate{mailboxID: mbox.ID, accountID: mustAccountID(t, server, admin), reached: make(chan struct{}), release: make(chan struct{})}
	ca := dialAndLogin(t, startACLPermissionGateServer(t, server.ResilientDB, gate), admin, adminPassword)
	defer gate.resume()

	result := make(chan error, 1)
	go func() {
		result <- ca.SetACL(shared, imap.RightsIdentifier(admin), imap.RightModificationReplace, imap.RightSet(db.AllACLRights)).Wait()
	}()
	select {
	case <-gate.reached:
	case <-time.After(5 * time.Second):
		t.Fatal("SETACL never reached the permission check")
	}
	require.NoError(t, co.DeleteACL(shared, imap.RightsIdentifier(admin)).Wait())
	gate.resume()

	select {
	case err := <-result:
		requireResponseCode(t, err, imap.ResponseCodeNoPerm, "the revoked administrator's SETACL")
	case <-time.After(5 * time.Second):
		t.Fatal("SETACL did not finish after releasing the permission check")
	}
	acl, err := co.GetACL(shared).Wait()
	require.NoError(t, err)
	require.Empty(t, entriesFor(acl, admin), "the revoked administrator is back in the ACL")
}

func createAccount(t *testing.T, server *common.TestServer, email string) {
	t.Helper()
	_, err := server.ResilientDB.CreateAccountWithRetry(context.Background(), db.CreateAccountRequest{
		Email: email, Password: "password", HashType: "bcrypt", IsPrimary: true,
	})
	require.NoError(t, err)
}

// TestACL_EntryFollowsAddressMoves: an entry belongs to an account, and an address can
// leave that account for another. GETACL must then show the entry under the account's
// current address, so that revoking what GETACL shows removes it, and granting the
// moved address to its new account must give that account an entry of its own rather
// than take over the old one.
func TestACL_EntryFollowsAddressMoves(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	ctx := context.Background()

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	moved, password := createSecondUser(t, server, "example.com", "moved")
	renamed := fmt.Sprintf("renamed-%d@example.com", common.GetTimestamp())
	co := dialAndLogin(t, server.Address, owner.Email, owner.Password)
	shared := fmt.Sprintf("Shared/Moves-%d", common.GetTimestamp())
	require.NoError(t, co.Create(shared, nil).Wait())
	defer func() { co.Delete(shared).Wait() }()
	require.NoError(t, co.SetACL(shared, imap.RightsIdentifier(moved), imap.RightModificationReplace, imap.RightSet("lr")).Wait())

	// The account takes a new primary address and gives up the old one, which a new
	// account then gets.
	require.NoError(t, server.ResilientDB.AddCredentialWithRetry(ctx, db.AddCredentialRequest{
		AccountID: mustAccountID(t, server, moved), NewEmail: renamed, NewPassword: password, NewHashType: "bcrypt", IsPrimary: true,
	}))
	require.NoError(t, server.ResilientDB.DeleteCredentialWithRetry(ctx, moved))
	createAccount(t, server, moved)
	cm := dialAndLogin(t, server.Address, renamed, password)

	acl, err := co.GetACL(shared).Wait()
	require.NoError(t, err)
	require.Equal(t, map[imap.RightsIdentifier]string{imap.RightsIdentifier(renamed): "lr"}, entriesFor(acl, renamed, moved))

	// The old address now names the new account, which holds nothing.
	require.NoError(t, co.DeleteACL(shared, imap.RightsIdentifier(moved)).Wait())
	_, err = cm.Select(shared, nil).Wait()
	require.NoError(t, err, "revoking the address's new account must leave the old one's entry")

	require.NoError(t, co.SetACL(shared, imap.RightsIdentifier(moved), imap.RightModificationReplace, imap.RightSet("l")).Wait())
	acl, err = co.GetACL(shared).Wait()
	require.NoError(t, err)
	require.Equal(t, map[imap.RightsIdentifier]string{imap.RightsIdentifier(renamed): "lr", imap.RightsIdentifier(moved): "l"},
		entriesFor(acl, renamed, moved), "granting the moved address must not take over the old account's entry")

	require.NoError(t, co.DeleteACL(shared, imap.RightsIdentifier(renamed)).Wait())
	_, err = cm.Select(shared, nil).Wait()
	require.Error(t, err, "revoking the address GETACL showed must remove the entry")
}

// TestACL_TakingRightsAwayAlwaysWorks: a grantee can stop being grantable (the
// account is deleted, or its primary address moves to another domain) while still
// holding rights, 'a' included. Removing rights from them must still work, since
// only adding rights is a grant; so must an administrator removing their own 'a'.
func TestACL_TakingRightsAwayAlwaysWorks(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	ctx := context.Background()

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	deleted, _ := createSecondUser(t, server, "example.com", "deleted")
	emigrant, _ := createSecondUser(t, server, "example.com", "emigrant")
	abroad := fmt.Sprintf("emigrant-%d@other.example.com", common.GetTimestamp())
	admin, adminPassword := createSecondUser(t, server, "example.com", "selfadmin")

	co := dialAndLogin(t, server.Address, owner.Email, owner.Password)
	shared := fmt.Sprintf("Shared/TakeAway-%d", common.GetTimestamp())
	require.NoError(t, co.Create(shared, nil).Wait())
	defer func() { co.Delete(shared).Wait() }()
	for _, id := range []string{deleted, emigrant, admin} {
		require.NoError(t, co.SetACL(shared, imap.RightsIdentifier(id), imap.RightModificationReplace, imap.RightSet("lra")).Wait())
	}
	require.NoError(t, server.ResilientDB.DeleteAccountWithRetry(ctx, deleted))
	require.NoError(t, server.ResilientDB.AddCredentialWithRetry(ctx, db.AddCredentialRequest{
		AccountID: mustAccountID(t, server, emigrant), NewEmail: abroad, NewPassword: "password", NewHashType: "bcrypt", IsPrimary: true,
	}))

	rightsOf := func(id string) string {
		t.Helper()
		acl, err := co.GetACL(shared).Wait()
		require.NoError(t, err)
		return acl.Rights[imap.RightsIdentifier(id)].String()
	}
	for _, id := range []string{deleted, emigrant, abroad} {
		require.NoError(t, co.SetACL(shared, imap.RightsIdentifier(id), imap.RightModificationRemove, imap.RightSet("x")).Wait(), "SETACL %s -x", id)
	}
	require.NoError(t, co.SetACL(shared, imap.RightsIdentifier(deleted), imap.RightModificationRemove, imap.RightSet("a")).Wait())
	require.Equal(t, "lr", rightsOf(deleted))
	require.NoError(t, co.SetACL(shared, imap.RightsIdentifier(emigrant), imap.RightModificationReplace, imap.RightSet("l")).Wait())
	require.Equal(t, "l", rightsOf(abroad), "the entry is listed under the grantee's new address")

	// Adding is still a grant, and these grantees can no longer be granted anything.
	requireResponseCode(t, co.SetACL(shared, imap.RightsIdentifier(deleted), imap.RightModificationAdd, imap.RightSet("w")).Wait(),
		imap.ResponseCodeNonExistent, "SETACL <deleted> +w")
	requireResponseCode(t, co.SetACL(shared, imap.RightsIdentifier(emigrant), imap.RightModificationAdd, imap.RightSet("w")).Wait(),
		imap.ResponseCodeCannot, "SETACL <emigrant> +w")

	ca := dialAndLogin(t, server.Address, admin, adminPassword)
	require.NoError(t, ca.SetACL(shared, imap.RightsIdentifier(admin), imap.RightModificationRemove, imap.RightSet("a")).Wait())
	require.Equal(t, "lr", rightsOf(admin))
}

// TestACL_LegacyDuplicateRowsNeverEscalate: before one row per account, an account
// could hold two rows under two spellings, and has_mailbox_right enforces whichever
// it reads first. GETACL shows every right either grants, but a change starts from
// the rights both grant, so an unrelated "+w" cannot switch on an 'a' that may not
// have been in effect. The change leaves one row.
func TestACL_LegacyDuplicateRowsNeverEscalate(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	ctx := context.Background()

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	member, _ := createSecondUser(t, server, "example.com", "dup")
	co := dialAndLogin(t, server.Address, owner.Email, owner.Password)
	shared := fmt.Sprintf("Shared/Dup-%d", common.GetTimestamp())
	require.NoError(t, co.Create(shared, nil).Wait())
	defer func() { co.Delete(shared).Wait() }()

	mbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, mustAccountID(t, server, owner.Email), shared)
	require.NoError(t, err)
	pool := server.ResilientDB.GetDatabase().GetWritePool()
	_, err = pool.Exec(ctx, `
		INSERT INTO mailbox_acls (mailbox_id, account_id, identifier, rights) VALUES ($1, $2, $3, 'l'), ($1, $2, $4, 'lra')`,
		mbox.ID, mustAccountID(t, server, member), member, strings.ToUpper(member))
	require.NoError(t, err)

	acl, err := co.GetACL(shared).Wait()
	require.NoError(t, err)
	require.Equal(t, map[imap.RightsIdentifier]string{imap.RightsIdentifier(member): "lra"}, entriesFor(acl, member))

	require.NoError(t, co.SetACL(shared, imap.RightsIdentifier(member), imap.RightModificationAdd, imap.RightSet("w")).Wait())
	var rows int
	var rights string
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*), max(rights) FROM mailbox_acls WHERE mailbox_id = $1 AND account_id = $2`,
		mbox.ID, mustAccountID(t, server, member)).Scan(&rows, &rights))
	require.Equal(t, 1, rows)
	require.Equal(t, "lw", rights)
}

// TestACL_AnyoneIsExact: "anyone" is the one special identifier, spelled exactly so.
// "ANYONE" is not an address either, so it names no one: granting to it is refused
// and revoking it leaves the real "anyone" entry alone.
func TestACL_AnyoneIsExact(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	co := dialAndLogin(t, server.Address, owner.Email, owner.Password)
	shared := fmt.Sprintf("Shared/Anyone-%d", common.GetTimestamp())
	require.NoError(t, co.Create(shared, nil).Wait())
	defer func() { co.Delete(shared).Wait() }()
	require.NoError(t, co.SetACL(shared, "anyone", imap.RightModificationReplace, imap.RightSet("lr")).Wait())

	require.NoError(t, co.DeleteACL(shared, "ANYONE").Wait())
	require.NoError(t, co.SetACL(shared, "ANYONE", imap.RightModificationRemove, imap.RightSet("lr")).Wait())
	requireResponseCode(t, co.SetACL(shared, "ANYONE", imap.RightModificationReplace, imap.RightSet("l")).Wait(),
		imap.ResponseCodeNonExistent, "SETACL ANYONE l")
	_, err := co.ListRights(shared, "ANYONE").Wait()
	requireResponseCode(t, err, imap.ResponseCodeNonExistent, "LISTRIGHTS ANYONE")

	acl, err := co.GetACL(shared).Wait()
	require.NoError(t, err)
	require.Equal(t, "lr", acl.Rights["anyone"].String())
}

// TestACL_OwnerAliasAbroadRevealsNothing: the owner can have an address in another
// domain. To a delegated administrator, LISTRIGHTS and SETACL for it must answer just
// as for any address in that domain, or they reveal which addresses are the owner's.
func TestACL_OwnerAliasAbroadRevealsNothing(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	ownerAbroad := fmt.Sprintf("owner-abroad-%d@other.example.com", common.GetTimestamp())
	addAlias(t, server, owner.Email, ownerAbroad)
	ghost := fmt.Sprintf("ghost-%d@other.example.com", common.GetTimestamp())
	admin, adminPassword := createSecondUser(t, server, "example.com", "abroadadmin")

	co := dialAndLogin(t, server.Address, owner.Email, owner.Password)
	shared := fmt.Sprintf("Shared/Abroad-%d", common.GetTimestamp())
	require.NoError(t, co.Create(shared, nil).Wait())
	defer func() { co.Delete(shared).Wait() }()
	require.NoError(t, co.SetACL(shared, imap.RightsIdentifier(admin), imap.RightModificationReplace, imap.RightSet("lra")).Wait())
	ca := dialAndLogin(t, server.Address, admin, adminPassword)

	answer := func(id string) string {
		t.Helper()
		data, err := ca.ListRights(shared, imap.RightsIdentifier(id)).Wait()
		require.NoError(t, err, "LISTRIGHTS %s", id)
		return fmt.Sprintf("listrights=%q/%q setacl=%v", data.RequiredRights, rightGroups(data),
			ca.SetACL(shared, imap.RightsIdentifier(id), imap.RightModificationReplace, imap.RightSet("l")).Wait())
	}
	require.Equal(t, strings.ReplaceAll(answer(ghost), ghost, "X"), strings.ReplaceAll(answer(ownerAbroad), ownerAbroad, "X"))
}

// TestACL_NoOwnerDomainStillRevokes: a shared mailbox without an owner domain (legacy
// data) can't take new grants, but its existing entries must still be revocable.
func TestACL_NoOwnerDomainStillRevokes(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	ctx := context.Background()

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	member, memberPassword := createSecondUser(t, server, "example.com", "nodomain")
	co := dialAndLogin(t, server.Address, owner.Email, owner.Password)
	shared := fmt.Sprintf("Shared/NoDomain-%d", common.GetTimestamp())
	require.NoError(t, co.Create(shared, nil).Wait())
	defer func() { co.Delete(shared).Wait() }()
	require.NoError(t, co.SetACL(shared, imap.RightsIdentifier(member), imap.RightModificationReplace, imap.RightSet("lr")).Wait())
	_, err := server.ResilientDB.GetDatabase().GetWritePool().Exec(ctx,
		`UPDATE mailboxes SET owner_domain = NULL WHERE account_id = $1 AND name = $2`, mustAccountID(t, server, owner.Email), shared)
	require.NoError(t, err)

	data, err := co.ListRights(shared, imap.RightsIdentifier(owner.Email)).Wait()
	require.NoError(t, err)
	require.True(t, hasAllRights(data.RequiredRights, imap.RightSet(db.AllACLRights)))
	require.NoError(t, co.SetACL(shared, imap.RightsIdentifier(member), imap.RightModificationRemove, imap.RightSet("r")).Wait())
	require.NoError(t, co.DeleteACL(shared, imap.RightsIdentifier(member)).Wait())
	cm := dialAndLogin(t, server.Address, member, memberPassword)
	_, err = cm.Select(shared, nil).Wait()
	require.Error(t, err)
}

// TestACL_GrantHoldsTheACLLock: the 'a' re-check only helps if no revoke can commit
// between it and the grant. With the delegated administrator's self-grant paused just
// after the re-check, the owner's revoke must wait for it, and then remove the
// administrator: the result of the grant followed by the revoke.
func TestACL_GrantHoldsTheACLLock(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	ctx := context.Background()

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	admin, adminPassword := createSecondUser(t, server, "example.com", "lockadmin")
	co := dialAndLogin(t, server.Address, owner.Email, owner.Password)
	shared := fmt.Sprintf("Shared/Lock-%d", common.GetTimestamp())
	require.NoError(t, co.Create(shared, nil).Wait())
	defer func() { co.Delete(shared).Wait() }()
	require.NoError(t, co.SetACL(shared, imap.RightsIdentifier(admin), imap.RightModificationReplace, imap.RightSet("lra")).Wait())

	mbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, mustAccountID(t, server, owner.Email), shared)
	require.NoError(t, err)
	gate := &aclPermissionGate{mailboxID: mbox.ID, accountID: mustAccountID(t, server, admin), inTransaction: true,
		reached: make(chan struct{}), release: make(chan struct{})}
	ca := dialAndLogin(t, startACLPermissionGateServer(t, server.ResilientDB, gate), admin, adminPassword)
	defer gate.resume()

	granted := make(chan error, 1)
	go func() {
		granted <- ca.SetACL(shared, imap.RightsIdentifier(admin), imap.RightModificationReplace, imap.RightSet(db.AllACLRights)).Wait()
	}()
	select {
	case <-gate.reached:
	case <-time.After(5 * time.Second):
		t.Fatal("SETACL never reached the re-check")
	}
	revoked := make(chan error, 1)
	go func() { revoked <- co.DeleteACL(shared, imap.RightsIdentifier(admin)).Wait() }()
	select {
	case err := <-revoked:
		t.Fatalf("the owner's DELETEACL finished (%v) while the grant held the ACL lock", err)
	case <-time.After(500 * time.Millisecond):
	}
	gate.resume()
	for name, ch := range map[string]chan error{"grant": granted, "revoke": revoked} {
		select {
		case err := <-ch:
			require.NoError(t, err, name)
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not finish", name)
		}
	}
	acl, err := co.GetACL(shared).Wait()
	require.NoError(t, err)
	require.Empty(t, entriesFor(acl, admin), "the revoke ran after the grant, so it must have removed the administrator")
}
