//go:build integration

package imap_test

import (
	"fmt"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// TestRename_SharedNamespaceBoundary covers issue #160. Whether a mailbox is shared
// (is_shared, owner_domain) is decided when it is created, from its name, and RENAME
// never updated it. A personal mailbox renamed into the shared namespace could not be
// shared, and a shared one renamed out of it kept its grantees in what the owner now
// saw as a personal folder. RENAME across the boundary can never be right, so it is
// refused with NO [CANNOT] (RFC 5530), before anything is created or changed.
func TestRename_SharedNamespaceBoundary(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	member, memberPassword := createSecondUser(t, server, "example.com", "boundary")

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()
	require.NoError(t, c.Login(owner.Email, owner.Password).Wait())

	ts := common.GetTimestamp()
	personal := fmt.Sprintf("Projects-%d", ts)
	shared := fmt.Sprintf("Shared/Team-%d", ts)
	for _, name := range []string{personal, shared} {
		require.NoError(t, c.Create(name, nil).Wait())
		defer func(name string) { c.Delete(name).Wait() }(name)
	}
	require.NoError(t, c.SetACL(shared, imap.RightsIdentifier(member), imap.RightModificationReplace, imap.RightSet("lr")).Wait())

	newParent := fmt.Sprintf("Shared/NewParent-%d", ts)
	for _, tc := range []struct{ from, to string }{
		{personal, fmt.Sprintf("Shared/Projects-%d", ts)},
		{personal, newParent + fmt.Sprintf("/Projects-%d", ts)},
		{shared, fmt.Sprintf("Team-%d", ts)},
		{"INBOX", fmt.Sprintf("Shared/Inbox-%d", ts)},
	} {
		err := c.Rename(tc.from, tc.to, nil).Wait()
		requireResponseCode(t, err, imap.ResponseCodeCannot, fmt.Sprintf("RENAME %s %s", tc.from, tc.to))
	}

	// Nothing moved, and the refused rename did not leave a new parent behind.
	names := listNames(t, c, "*")
	require.Contains(t, names, personal)
	require.Contains(t, names, shared)
	require.NotContains(t, names, newParent)

	// The grantee still has the shared mailbox, under its shared name.
	cm, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer cm.Logout()
	require.NoError(t, cm.Login(member, memberPassword).Wait())
	_, err = cm.Select(shared, nil).Wait()
	require.NoError(t, err)
}

// TestRename_ParentCreatedInSharedNamespaceIsShared: a RENAME inside the shared
// namespace may have to create the new parent, as CREATE would. That parent must be
// a shared mailbox like any other created there; RENAME used to create it without
// the shared-namespace settings, as a personal mailbox under the shared prefix.
func TestRename_ParentCreatedInSharedNamespaceIsShared(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	member, _ := createSecondUser(t, server, "example.com", "renameparent")

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()
	require.NoError(t, c.Login(owner.Email, owner.Password).Wait())

	ts := common.GetTimestamp()
	from := fmt.Sprintf("Shared/Leaf-%d", ts)
	parent := fmt.Sprintf("Shared/Parent-%d", ts)
	to := parent + fmt.Sprintf("/Leaf-%d", ts)
	require.NoError(t, c.Create(from, nil).Wait())
	defer func() {
		c.Delete(to).Wait()
		c.Delete(parent).Wait()
		c.Delete(from).Wait()
	}()

	require.NoError(t, c.Rename(from, to, nil).Wait())
	require.Contains(t, listNames(t, c, parent), parent)
	require.NoError(t, c.SetACL(parent, imap.RightsIdentifier(member), imap.RightModificationReplace, imap.RightSet("l")).Wait(),
		"the parent RENAME created must be shared")
}

func listNames(t *testing.T, c *imapclient.Client, pattern string) []string {
	t.Helper()
	mailboxes, err := c.List("", pattern, nil).Collect()
	require.NoError(t, err)
	names := make([]string, 0, len(mailboxes))
	for _, m := range mailboxes {
		names = append(names, m.Mailbox)
	}
	return names
}
