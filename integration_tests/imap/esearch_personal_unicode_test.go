//go:build integration

package imap_test

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func TestIMAP_PersonalUnicodeNamespace(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	for _, tc := range []struct {
		prefix, name string
		shared       bool
	}{
		{"Shared/", "ſhared/Child", false},
		{"ΑΣ/", "ας/Child", false},
		{"İx/", "ix/Child", true},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			cfg := config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: tc.prefix, AllowUserCreate: true, DefaultRights: "lrswipkxtea"}
			require.Equal(t, tc.shared, cfg.InNamespace(tc.name), "fixture must match actual CREATE classification")
			srv, account := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{SharedMailboxes: &cfg})
			defer srv.Close()
			conn, r := esearchDialLogin(t, srv, account.Email, account.Password)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Second)))
			esearchCmdOK(t, conn, r, "v", "ENABLE IMAP4rev2")
			esearchCreate(t, conn, r, "c", tc.name)
			esearchAppend(t, conn, r, "a", tc.name, "personal-unicode-probe")
			accountID, err := srv.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
			require.NoError(t, err)
			var shared bool
			require.NoError(t, srv.ResilientDB.QueryRowWithRetry(context.Background(), `SELECT is_shared FROM mailboxes WHERE account_id=$1 AND name=$2`, accountID, tc.name).Scan(&shared))
			require.Equal(t, tc.shared, shared)
			esearchCmdOK(t, conn, r, "s", "SELECT "+esearchQuote(tc.name))
			got := esearchMailboxes(t, esearchCmdOK(t, conn, r, "p", `ESEARCH IN (PERSONAL) RETURN (ALL) SUBJECT "personal-unicode-probe"`))
			if tc.shared {
				if _, ok := got[tc.name]; ok {
					t.Errorf("shared mailbox %q returned by PERSONAL: %v", tc.name, got)
				}
			} else {
				esearchAssertHas(t, got, tc.name)
			}
		})
	}
}
