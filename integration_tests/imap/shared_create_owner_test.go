//go:build integration

package imap_test

import (
	"context"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func TestSharedMailboxes_DelegatedCreateUsesHierarchyOwner(t *testing.T) {
	for _, rights := range []string{"lkr", "kr"} {
		t.Run(rights, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServerWithOptions(t, sharedMailboxSettings(false, true))
			defer server.Close()
			member, password := createSecondUser(t, server, "example.com", "create-owner")
			ctx := context.WithValue(context.Background(), consts.ConfigContextKey, &config.Config{SharedMailboxes: config.SharedMailboxesConfig{
				Enabled: true, NamespacePrefix: "Shared/", AllowUserCreate: true, DefaultRights: "lrswipkxtea",
			}})
			ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(ctx, owner.Email)
			require.NoError(t, err)
			memberID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(ctx, member)
			require.NoError(t, err)
			require.NoError(t, server.ResilientDB.CreateMailboxForUserWithRetry(ctx, ownerID, "Shared/Team"))
			c, err := imapclient.DialInsecure(server.Address, nil)
			require.NoError(t, err)
			defer c.Logout()
			require.NoError(t, c.Login(owner.Email, owner.Password).Wait())
			require.NoError(t, c.SetACL("Shared/Team", imap.RightsIdentifier(member), imap.RightModificationReplace, imap.RightSet(rights)).Wait())
			m, err := imapclient.DialInsecure(server.Address, nil)
			require.NoError(t, err)
			defer m.Logout()
			require.NoError(t, m.Login(member, password).Wait())
			for _, name := range []string{"Shared/Team/Child", "Shared/Team/Sub/Deep/Leaf"} {
				require.NoError(t, m.Create(name, nil).Wait(), "k right must permit creating in the shared owner's hierarchy")
				mailbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, ownerID, name)
				require.NoError(t, err)
				require.Equal(t, ownerID, mailbox.AccountID)
				root, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, ownerID, "Shared/Team")
				require.NoError(t, err)
				require.True(t, strings.HasPrefix(mailbox.Path, root.Path), "child path must stay in owner's tree")
				inherited, err := server.ResilientDB.GetUserMailboxRightsWithRetry(ctx, mailbox.ID, memberID)
				require.NoError(t, err)
				require.Contains(t, inherited, "r", "new shared mailbox must inherit delegated read right")
			}
			// The immediate parent's k right suffices even if its shared root is hidden.
			require.NoError(t, c.SetACL("Shared/Team", imap.RightsIdentifier(member), imap.RightModificationReplace, imap.RightSet("")).Wait())
			require.NoError(t, m.Create("Shared/Team/Child/Grandchild", nil).Wait())
			// A user lacking k must be refused before creating any missing parent.
			require.NoError(t, c.SetACL("Shared/Team", imap.RightsIdentifier(member), imap.RightModificationReplace, imap.RightSet("lr")).Wait())
			requireResponseCode(t, m.Create("Shared/Team/Denied/Child", nil).Wait(), imap.ResponseCodeNoPerm, "create without k")
			_, err = server.ResilientDB.GetMailboxByNameWithRetry(ctx, ownerID, "Shared/Team/Denied")
			require.ErrorIs(t, err, consts.ErrMailboxNotFound)
			var memberRoots int
			require.NoError(t, server.ResilientDB.QueryRowWithRetry(ctx, "SELECT count(*) FROM mailboxes WHERE account_id=$1 AND LOWER(name)='shared' AND deleted_at IS NULL", memberID).Scan(&memberRoots))
			require.Zero(t, memberRoots, "delegated CREATE must not leak its own namespace root")
		})
	}
}
