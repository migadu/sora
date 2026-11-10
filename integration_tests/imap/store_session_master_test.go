//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	serverimap "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/require"
)

func TestIMAP_StoreSessionMasterPin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	source, owner := common.SetupIMAPServer(t)
	defer source.Close()
	co := dialRawIMAP(t, source.Address)
	co.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	co.appendMsg("INBOX", "Message-ID: <pin@example.com>\r\nSubject: pin\r\n\r\nbody\r\n")
	co.do("SELECT INBOX")

	ctx := context.Background()
	cfg := source.ResilientDB.GetDatabase().GetWritePool().Config().ConnConfig
	rdb, err := resilient.NewResilientDatabase(ctx, &config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
		Hosts: []string{cfg.Host}, Port: fmt.Sprint(cfg.Port), User: cfg.User, Password: cfg.Password, Name: cfg.Database,
	}}, false, false)
	require.NoError(t, err)
	t.Cleanup(rdb.Close)
	database := rdb.GetDatabase()
	schema := fmt.Sprintf("store_session_replica_%d", time.Now().UnixNano())
	_, err = database.WritePool.Exec(ctx, "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = database.WritePool.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE") })
	for _, table := range []string{"messages", "message_state"} {
		_, err := database.WritePool.Exec(ctx, fmt.Sprintf("CREATE TABLE %s.%s AS SELECT * FROM public.%s WHERE false", schema, table, table))
		require.NoError(t, err)
	}
	poolCfg := database.WritePool.Config().Copy()
	poolCfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	replica, err := pgxpool.NewWithConfig(ctx, poolCfg)
	require.NoError(t, err)
	t.Cleanup(replica.Close)
	// Install the divergent read view before starting the protocol server.
	database.ReadPool = replica
	addr := common.GetRandomAddress(t)
	srv, err := serverimap.New(ctx, "store-master-pin", "localhost", addr, &storage.S3Storage{}, rdb, nil, nil, serverimap.IMAPServerOptions{InsecureAuth: true})
	require.NoError(t, err)
	go func() { _ = srv.Serve(addr) }()
	t.Cleanup(func() { srv.Close() })
	require.Eventually(t, func() bool {
		c, err := imapclient.DialInsecure(addr, nil)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond)
	c := dialRawIMAP(t, addr)
	c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	c.do("SELECT INBOX")
	store := func() { c.do(`UID STORE 1 +FLAGS (\Flagged)`) }
	flags := func() string { lines, _ := co.do("UID FETCH 1 FLAGS"); return strings.Join(lines, " ") }
	store()
	require.NotContains(t, flags(), `\Flagged`, "control: the unpinned replica has no message to update")
	c.do("CREATE PinSession")
	store()
	require.Contains(t, flags(), `\Flagged`, "STORE must propagate the session master pin")
}
