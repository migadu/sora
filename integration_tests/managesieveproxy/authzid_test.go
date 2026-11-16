//go:build integration

package managesieveproxy_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func TestManageSieveProxyAuthorizationIdentityUsesProvenAccount(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	backend, account := common.SetupManageSieveServerWithMaster(t)
	t.Cleanup(backend.Close)
	other := common.CreateTestAccount(t, backend.ResilientDB)
	ctx := context.Background()
	for name, email := range map[string]string{"owner-only": account.Email, "other-only": other.Email} {
		id, err := backend.ResilientDB.GetAccountIDByEmailWithRetry(ctx, email)
		require.NoError(t, err)
		_, err = backend.ResilientDB.CreateScriptWithRetry(ctx, id, name, "keep;")
		require.NoError(t, err)
	}
	addr := common.GetRandomAddress(t)
	setupManageSieveProxyWithMasterAuth(t, backend, addr, []string{backend.Address})
	for _, tc := range []struct {
		name, authz, authn, password string
		refused                      bool
	}{
		{"own", account.Email, account.Email, account.Password, false},
		{"other account", other.Email, account.Email, account.Password, true},
		{"master target", account.Email, account.Email + "@" + proxyMasterUsername, proxyMasterPassword, false},
		{"master other target", other.Email, account.Email + "@" + proxyMasterUsername, proxyMasterPassword, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewManageSieveClient(addr)
			require.NoError(t, err)
			defer c.conn.Close()
			authenticate := func(authz, authn, password string) string {
				encoded := base64.StdEncoding.EncodeToString([]byte(authz + "\x00" + authn + "\x00" + password))
				require.NoError(t, c.SendCommand(`AUTHENTICATE "PLAIN" "`+encoded+`"`))
				reply, err := c.ReadResponse()
				require.NoError(t, err)
				return reply
			}
			reply := authenticate(tc.authz, tc.authn, tc.password)
			if tc.refused {
				require.Equal(t, `NO "Proxy authentication requires master credentials"`, reply)
				require.NoError(t, c.SendCommand("LISTSCRIPTS"))
				reply, err = c.ReadResponse()
				require.NoError(t, err)
				require.True(t, strings.HasPrefix(reply, "NO"), "refused authorization must not expose scripts: %s", reply)
				reply = authenticate("", account.Email, account.Password)
			}
			require.True(t, strings.HasPrefix(reply, "OK"), "%s", reply)
			require.NoError(t, c.SendCommand("LISTSCRIPTS"))
			var listed []string
			for {
				line, err := c.ReadResponse()
				require.NoError(t, err)
				if strings.HasPrefix(line, "OK") {
					break
				}
				require.False(t, strings.HasPrefix(line, "NO"), "%s", line)
				listed = append(listed, line)
			}
			require.Contains(t, strings.Join(listed, "\n"), "owner-only")
			require.NotContains(t, strings.Join(listed, "\n"), "other-only")
		})
	}
}
