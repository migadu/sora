//go:build integration

package imap_test

import (
	"context"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// RFC 3501 §6.3.5 requires descendant renames and recommends creating all
// superior names. Every newly created shared parent must inherit Sora's ACLs.
func TestRename_AutoCreatedParentsInheritAndCascade(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServerWithOptions(t, sharedMailboxSettings(false, true))
	defer server.Close()
	member, password := createSecondUser(t, server, "example.com", "parentchain")
	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()
	require.NoError(t, c.Login(owner.Email, owner.Password).Wait())
	// An administrator creates the root; delegates may extend its hierarchy with
	// the k right even while creating new shared roots is disabled (#159).
	adminCtx := context.WithValue(context.Background(), consts.ConfigContextKey, &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/", AllowUserCreate: true},
	})
	ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(adminCtx, owner.Email)
	require.NoError(t, err)
	require.NoError(t, server.ResilientDB.CreateMailboxForUserWithRetry(adminCtx, ownerID, "Shared/Team"))
	require.NoError(t, c.Create("Shared/Team/Leaf", nil).Wait())
	for _, name := range []string{"Shared/Team", "Shared/Team/Leaf"} {
		require.NoError(t, c.SetACL(name, imap.RightsIdentifier(member), imap.RightModificationReplace, imap.RightSet("lrswipkxtea")).Wait())
	}
	cm, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer cm.Logout()
	require.NoError(t, cm.Login(member, password).Wait())
	require.NoError(t, cm.Rename("Shared/Team/Leaf", "Shared/Team/Sub/Deep/Leaf", nil).Wait())
	for _, name := range []string{"Shared/Team/Sub", "Shared/Team/Sub/Deep"} {
		_, err := cm.Select(name, nil).Wait()
		require.NoError(t, err, "auto-created parent must inherit delegated rights: %s", name)
	}
	require.NoError(t, c.Rename("Shared/Team", "Shared/RenamedTeam", nil).Wait())
	names := listNames(t, c, "*")
	for _, suffix := range []string{"", "/Sub", "/Sub/Deep", "/Sub/Deep/Leaf"} {
		require.Contains(t, names, "Shared/RenamedTeam"+suffix)
		require.NotContains(t, names, "Shared/Team"+suffix)
	}
}

func TestRename_CreatesEveryMissingAncestor(t *testing.T) {
	for _, source := range []string{"Leaf", "INBOX"} {
		t.Run(source, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServer(t)
			defer server.Close()
			c, err := imapclient.DialInsecure(server.Address, nil)
			require.NoError(t, err)
			defer c.Logout()
			require.NoError(t, c.Login(owner.Email, owner.Password).Wait())
			if source != "INBOX" {
				require.NoError(t, c.Create(source, nil).Wait())
			}
			require.NoError(t, c.Rename(source, "A/B/Leaf", nil).Wait())
			names := listNames(t, c, "*")
			for _, name := range []string{"A", "A/B", "A/B/Leaf"} {
				require.Contains(t, names, name)
			}
			require.NoError(t, c.Rename("A", "RenamedA", nil).Wait())
			require.Contains(t, listNames(t, c, "*"), "RenamedA/B/Leaf")
		})
	}
}
