//go:build integration

package imapproxy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/emersion/go-sasl"
	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func TestIMAPProxyAuthorizationIdentityUsesProvenAccount(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	backend, account := common.SetupIMAPServerWithMaster(t)
	t.Cleanup(backend.Close)
	other := common.CreateTestAccount(t, backend.ResilientDB)
	ctx := context.Background()
	accountID, err := backend.ResilientDB.GetAccountIDByEmailWithRetry(ctx, account.Email)
	require.NoError(t, err)
	inbox, err := backend.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)
	addr := common.GetRandomAddress(t)
	setupIMAPProxyWithMasterAuth(t, backend, addr, []string{backend.Address})

	for _, tc := range []struct {
		name, authz, authn, password string
		refused                      bool
	}{
		{"own", account.Email, account.Email, account.Password, false},
		{"base for detail", account.Email, strings.Replace(account.Email, "@", "+tag@", 1), account.Password, false},
		{"other account", other.Email, account.Email, account.Password, true},
		{"master target", account.Email, account.Email + "@" + proxyMasterUsername, proxyMasterPassword, false},
		{"master other target", other.Email, account.Email + "@" + proxyMasterUsername, proxyMasterPassword, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := imapclient.DialInsecure(addr, nil)
			require.NoError(t, err)
			defer c.Close()
			err = c.Authenticate(sasl.NewPlainClient(tc.authz, tc.authn, tc.password))
			if tc.refused {
				require.ErrorContains(t, err, "AUTHORIZATIONFAILED")
				require.Equal(t, imap.ConnStateNotAuthenticated, c.State(), "a refused authorization must leave the connection unauthenticated")
				require.NoError(t, c.Authenticate(sasl.NewPlainClient("", account.Email, account.Password)))
			} else {
				require.NoError(t, err)
			}
			selected, err := c.Select("INBOX", nil).Wait()
			require.NoError(t, err)
			require.Equal(t, inbox.UIDValidity, selected.UIDValidity, "backend session must reach the proven account")
		})
	}
}
