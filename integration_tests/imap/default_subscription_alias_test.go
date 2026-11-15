//go:build integration

package imap_test

import (
	"context"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func TestIMAP_DefaultSubscriptionUnicodeRecovery(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	for _, ordinary := range []bool{false, true} {
		name := "canonical_default_legacy_alias"
		if ordinary {
			name = "ordinary_unicode_physical_row"
		}
		t.Run(name, func(t *testing.T) {
			srv, account := common.SetupIMAPServer(t)
			defer srv.Close()
			c := notifyLoginAndSelect(t, srv.Address, account, nil, "")
			defer c.Logout()
			ctx := context.Background()
			id, err := srv.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
			require.NoError(t, err)
			// Prepare an upgrade/recovery state; these direct edits are fixture
			// setup, while every subscription and DELETE operation is real IMAP.
			_, err = srv.ResilientDB.ExecWithRetry(ctx, "DELETE FROM subscriptions WHERE account_id=$1 AND LOWER(mailbox_name)=LOWER($2)", id, "Junk")
			require.NoError(t, err)
			if ordinary {
				_, err = srv.ResilientDB.ExecWithRetry(ctx, "DELETE FROM mailboxes WHERE account_id=$1 AND name='Junk'", id)
				require.NoError(t, err)
				require.NoError(t, c.Create("Jun\u212A", nil).Wait())
			}
			require.NoError(t, c.Subscribe("Jun\u212A").Wait())
			require.NoError(t, c.Unsubscribe("JUNK").Wait())
			names := listMailboxNames(t, c, &imap.ListOptions{SelectSubscribed: true})
			if ordinary {
				require.False(t, names["Jun\u212A"], "ordinary stored Unicode row must be removable")
				require.NoError(t, c.Delete("Jun\u212A").Wait())
				require.False(t, listMailboxNames(t, c, nil)["Jun\u212A"])
			} else {
				require.True(t, names["Junk"], "canonical default's legacy subscription must stay")
			}
		})
	}
}
