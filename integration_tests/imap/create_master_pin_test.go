//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func TestIMAP_HierarchyCommandsKeepMasterPin(t *testing.T) {
	for _, operation := range []string{"CREATE", "RENAME"} {
		t.Run(operation, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServer(t)
			defer server.Close()
			c, err := imapclient.DialInsecure(server.Address, nil)
			require.NoError(t, err)
			defer c.Logout()
			require.NoError(t, c.Login(owner.Email, owner.Password).Wait())
			require.NoError(t, c.Create("Parent", nil).Wait(), "first write pins the session")

			ctx := context.Background()
			database := server.ResilientDB.GetOperationalDatabase()
			ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(ctx, owner.Email)
			require.NoError(t, err)
			schema := fmt.Sprintf("create_pin_replica_%d", time.Now().UnixNano())
			_, err = database.WritePool.Exec(ctx, "CREATE SCHEMA "+schema)
			require.NoError(t, err)
			defer database.WritePool.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
			_, err = database.WritePool.Exec(ctx, "CREATE TABLE "+schema+".mailboxes AS SELECT * FROM public.mailboxes WHERE false")
			require.NoError(t, err)
			poolCfg := database.ReadPool.Config().Copy()
			poolCfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
			lagging, err := pgxpool.NewWithConfig(ctx, poolCfg)
			require.NoError(t, err)
			original := database.ReadPool
			database.ReadPool = lagging
			defer func() { database.ReadPool = original; lagging.Close() }()
			_, err = database.GetMailboxByName(ctx, ownerID, "Parent")
			require.ErrorIs(t, err, consts.ErrMailboxNotFound, "control: the replica must lag behind the first write")
			if operation == "CREATE" {
				require.NoError(t, c.Create("Parent/Child", nil).Wait(), "the same session must resolve its newly created parent on the writer")
			} else {
				require.NoError(t, c.Rename("Parent", "Other/Parent", nil).Wait(), "rename prechecks must resolve the source and its ACLs on the writer")
			}
		})
	}
}
