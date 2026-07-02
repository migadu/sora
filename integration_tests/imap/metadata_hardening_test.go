//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// TestIMAP_MetadataEntryNameCaseInsensitive verifies RFC 5464 §3.1: entry names
// are case-insensitive. A value stored under one casing must be retrievable via
// any other casing (canonicalised to lower case). Also checks the widened
// character allowlist accepts RFC-valid entry-name characters that the old
// [a-zA-Z0-9/_.-] allowlist rejected.
func TestIMAP_MetadataEntryNameCaseInsensitive(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()
	require.NoError(t, c.Login(account.Email, account.Password).Wait())

	// Store under mixed case.
	val := []byte("hello")
	require.NoError(t, c.SetMetadata("", map[string]*[]byte{"/private/Comment": &val}).Wait())

	// Retrieve under a DIFFERENT case — must resolve to the same entry.
	res, err := c.GetMetadata("", []string{"/PRIVATE/COMMENT"}, nil).Wait()
	require.NoError(t, err)
	got, ok := res.Entries["/private/comment"] // canonical (lower-case) key
	require.True(t, ok, "case-insensitive lookup returned no entry; entries=%v", res.Entries)
	require.NotNil(t, got)
	require.Equal(t, "hello", string(*got))

	// Widened character set: ':' is a valid RFC 5464 entry-name character that the
	// old allowlist rejected. It must now be accepted.
	val2 := []byte("x")
	require.NoError(t, c.SetMetadata("", map[string]*[]byte{"/private/vendor:coi": &val2}).Wait(),
		"RFC-valid entry name with ':' should be accepted")

	// '*' and '%' remain forbidden (RFC 5464 §3.1).
	err = c.SetMetadata("", map[string]*[]byte{"/private/bad*name": &val2}).Wait()
	require.Error(t, err, "entry name containing '*' must be rejected")
}

// TestIMAP_MetadataSharedScopeACLNotBypassableByCase verifies that the
// /private-vs-/shared scope classification is case-insensitive so it cannot be
// evaded by spelling the prefix in upper case. A grantee with only 'l'+'r' (no
// 'w') must NOT be able to set a shared-scope entry — regardless of casing.
//
// Before the fix, needsWrite used a case-sensitive HasPrefix("/shared/"), so
// "/SHARED/x" was misclassified as private (needing only 'l') and the write
// slipped through — an ACL bypass (RED).
func TestIMAP_MetadataSharedScopeACLNotBypassableByCase(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	domain := strings.Split(account1.Email, "@")[1]
	email2 := fmt.Sprintf("user2-%d@%s", common.GetTimestamp(), domain)
	if _, err := server.ResilientDB.CreateAccountWithRetry(context.Background(), db.CreateAccountRequest{
		Email:     email2,
		Password:  "password2",
		HashType:  "bcrypt",
		IsPrimary: true,
	}); err != nil {
		t.Fatalf("failed to create second user: %v", err)
	}

	// User1 creates a shared mailbox and grants user2 lookup+read only (NO write).
	c1, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c1.Logout()
	require.NoError(t, c1.Login(account1.Email, account1.Password).Wait())

	sharedMailbox := fmt.Sprintf("Shared/MetaACL-%d", common.GetTimestamp())
	require.NoError(t, c1.Create(sharedMailbox, nil).Wait())
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	accountID1, _ := server.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account1.Email)
	require.NoError(t, server.ResilientDB.GrantMailboxAccessByIdentifierWithRetry(
		context.Background(), accountID1, email2, sharedMailbox, "lr"))

	// User2 connects with only l+r rights.
	c2, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c2.Logout()
	require.NoError(t, c2.Login(email2, "password2").Wait())

	val := []byte("x")

	// Lower-case shared entry: must be rejected (control — always was).
	require.Error(t, c2.SetMetadata(sharedMailbox, map[string]*[]byte{"/shared/foo": &val}).Wait(),
		"grantee without 'w' must not set a /shared entry")

	// Upper-case shared entry: must ALSO be rejected (the bypass this fix closes).
	require.Error(t, c2.SetMetadata(sharedMailbox, map[string]*[]byte{"/SHARED/foo": &val}).Wait(),
		"grantee without 'w' must not set a /SHARED entry via case-spelling (ACL bypass)")

	// Sanity: user1 (owner, all rights) CAN set the shared entry, either casing.
	require.NoError(t, c1.SetMetadata(sharedMailbox, map[string]*[]byte{"/SHARED/foo": &val}).Wait())
}
