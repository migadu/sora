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

func TestIMAP_MultiSearchSessionMasterPin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	source, owner := common.SetupIMAPServer(t)
	defer source.Close()
	co := dialRawIMAP(t, source.Address)
	co.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	co.appendMsg("INBOX", "Message-ID: <pin@example.com>\r\nSubject: pin\r\n\r\nbody\r\n")

	ctx := context.Background()
	cfg := source.ResilientDB.GetDatabase().GetWritePool().Config().ConnConfig
	rdb, err := resilient.NewResilientDatabase(ctx, &config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
		Hosts: []string{cfg.Host}, Port: fmt.Sprint(cfg.Port), User: cfg.User, Password: cfg.Password, Name: cfg.Database,
	}}, false, false)
	require.NoError(t, err)
	t.Cleanup(rdb.Close)
	database := rdb.GetDatabase()
	schema := fmt.Sprintf("multisearch_session_replica_%d", time.Now().UnixNano())
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
	srv, err := serverimap.New(ctx, "multisearch-master-pin", "localhost", addr, &storage.S3Storage{}, rdb, nil, nil, serverimap.IMAPServerOptions{InsecureAuth: true})
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
	search := func() string {
		lines, _ := c.do("ESEARCH IN (mailboxes INBOX) RETURN (ALL) ALL")
		for _, line := range lines {
			if _, found, ok := strings.Cut(line, " UID ALL "); ok {
				return found
			}
		}
		return ""
	}
	require.Equal(t, "", search(), "control: the unpinned replica is empty")
	c.do("CREATE PinSession") // successful write pins subsequent reads to master
	require.Equal(t, "1", search(), "ESEARCH must propagate the session master pin")
}
