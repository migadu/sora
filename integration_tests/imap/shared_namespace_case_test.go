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

func TestSharedNamespaceCasePreservesPolicyAndClassification(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	for _, prefix := range []string{"Shared/", "#Team/", "Public/Rooms/"} {
		for _, allow := range []bool{false, true} {
			t.Run(prefix+"/allow="+map[bool]string{false: "false", true: "true"}[allow], func(t *testing.T) {
				server, owner := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{SharedMailboxes: &config.SharedMailboxesConfig{
					Enabled: true, NamespacePrefix: prefix, AllowUserCreate: allow, DefaultRights: "lrswipkxtea",
				}})
				defer server.Close()
				c, err := imapclient.DialInsecure(server.Address, nil)
				require.NoError(t, err)
				defer c.Logout()
				require.NoError(t, c.Login(owner.Email, owner.Password).Wait())
				// Case changes cannot turn the reserved namespace root into a personal mailbox.
				t.Run("namespace-root", func(t *testing.T) {
					requireResponseCode(t, c.Create(strings.ToLower(strings.TrimSuffix(prefix, "/")), nil).Wait(), imap.ResponseCodeCannot, "namespace root")
				})
				name := strings.ToLower(prefix) + "Team"
				err = c.Create(name, nil).Wait()
				if !allow {
					requireResponseCode(t, err, imap.ResponseCodeNoPerm, "case-insensitive shared policy")
					adminCfg := &config.Config{SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: prefix, AllowUserCreate: true, DefaultRights: "lrswipkxtea"}}
					adminCtx := context.WithValue(context.Background(), consts.ConfigContextKey, adminCfg)
					ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(adminCtx, owner.Email)
					require.NoError(t, err)
					require.NoError(t, server.ResilientDB.CreateMailboxForUserWithRetry(adminCtx, ownerID, prefix+"Existing"))
					require.NoError(t, c.Create(strings.ToLower(prefix)+"existing/Child", nil).Wait(), "case variants may extend an existing shared root")
					return
				}
				require.NoError(t, err)
				var shared bool
				require.NoError(t, server.ResilientDB.QueryRowWithRetry(context.Background(), `SELECT is_shared FROM mailboxes m JOIN credentials c ON c.account_id=m.account_id AND c.primary_identity WHERE LOWER(m.name)=LOWER($1) AND c.address=$2 AND m.deleted_at IS NULL`, name, owner.Email).Scan(&shared))
				require.True(t, shared, "case variant must not create an unshareable personal mailbox")
				_, err = c.Select(strings.ToLower(strings.TrimSuffix(prefix, "/")), nil).Wait()
				requireResponseCode(t, err, imap.ResponseCodeCannot, "case variant namespace root stays non-selectable")
				require.NoError(t, c.Rename(name, prefix+"Renamed", nil).Wait(), "case variant source stays in the same shared namespace")
			})
		}
	}
}
