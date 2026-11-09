//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	serverimap "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/require"
)

type storeSnapshotGate struct {
	mailboxID        int64
	armed, paused    atomic.Bool
	reached, release chan struct{}
	once             sync.Once
}
type storeSnapshotGateKey struct{}

func (g *storeSnapshotGate) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if g.armed.Load() && strings.Contains(q.SQL, "m.uid >") && strings.Contains(q.SQL, "LEFT JOIN message_state") && len(q.Args) > 0 && q.Args[0] == g.mailboxID {
		return context.WithValue(ctx, storeSnapshotGateKey{}, true)
	}
	return ctx
}
func (g *storeSnapshotGate) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryEndData) {
	if ctx.Value(storeSnapshotGateKey{}) != true || q.Err != nil || !g.paused.CompareAndSwap(false, true) {
		return
	}
	close(g.reached)
	select {
	case <-g.release:
	case <-ctx.Done():
	}
}
func (g *storeSnapshotGate) resume() { g.once.Do(func() { close(g.release) }) }

func startStoreSnapshotServer(t *testing.T, source *resilient.ResilientDatabase, gate *storeSnapshotGate) string {
	t.Helper()
	ctx := context.Background()
	cfg := source.GetDatabase().WritePool.Config().ConnConfig
	rdb, err := resilient.NewResilientDatabase(ctx, &config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{Hosts: []string{cfg.Host}, Port: fmt.Sprint(cfg.Port), User: cfg.User, Password: cfg.Password, Name: cfg.Database}}, false, false)
	require.NoError(t, err)
	t.Cleanup(rdb.Close)
	database := rdb.GetDatabase()
	old := database.WritePool
	poolCfg := old.Config().Copy()
	poolCfg.ConnConfig.Tracer = gate
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	require.NoError(t, err)
	database.WritePool, database.ReadPool = pool, pool
	old.Close()
	addr := common.GetRandomAddress(t)
	srv, err := serverimap.New(ctx, "store-snapshot", "localhost", addr, &storage.S3Storage{}, rdb, nil, nil, serverimap.IMAPServerOptions{InsecureAuth: true})
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
	return addr
}

func TestIMAP_StoreUnchangedSinceChecksAtWrite(t *testing.T) {
	for _, op := range []string{"FLAGS", "+FLAGS", "-FLAGS"} {
		t.Run(map[string]string{"FLAGS": "set", "+FLAGS": "add", "-FLAGS": "remove"}[op], func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServer(t)
			defer server.Close()
			writer := dialRawIMAP(t, server.Address)
			writer.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			writer.appendMsg("INBOX", "Subject: race\r\n\r\nbody\r\n")
			writer.do("SELECT INBOX")
			writer.do(`UID STORE 1 FLAGS (\Seen \Flagged)`)
			ctx := context.Background()
			ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(ctx, owner.Email)
			require.NoError(t, err)
			mailbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, ownerID, "INBOX")
			require.NoError(t, err)
			var cutoff uint64
			require.NoError(t, server.ResilientDB.QueryRowWithRetry(ctx, `SELECT greatest(m.created_modseq,coalesce(ms.updated_modseq,0)) FROM messages m JOIN message_state ms ON ms.message_id=m.id AND ms.mailbox_id=m.mailbox_id WHERE m.mailbox_id=$1 AND m.uid=1`, mailbox.ID).Scan(&cutoff))
			gate := &storeSnapshotGate{mailboxID: mailbox.ID, reached: make(chan struct{}), release: make(chan struct{})}
			defer gate.resume()
			addr := startStoreSnapshotServer(t, server.ResilientDB, gate)
			c := dialRawIMAP(t, addr)
			c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			c.do("SELECT INBOX (CONDSTORE)")
			gate.armed.Store(true)
			done := make(chan string, 1)
			go func() {
				_, tagged := c.do(fmt.Sprintf(`UID STORE 1 (UNCHANGEDSINCE %d) %s (\Flagged)`, cutoff, op))
				done <- tagged
			}()
			select {
			case <-gate.reached:
			case <-time.After(5 * time.Second):
				t.Fatal("STORE did not reach snapshot gate")
			}
			writer.do(`UID STORE 1 +FLAGS (\Answered)`)
			gate.resume()
			select {
			case tagged := <-done:
				require.Contains(t, tagged, "MODIFIED 1")
			case <-time.After(5 * time.Second):
				t.Fatal("STORE did not finish")
			}
			lines, _ := writer.do("UID FETCH 1 FLAGS")
			require.Contains(t, strings.Join(lines, " "), `\Answered`)
			require.Contains(t, strings.Join(lines, " "), `\Seen`)
			require.Contains(t, strings.Join(lines, " "), `\Flagged`)
		})
	}
}

func TestIMAP_StoreSilentReturnsModSeq(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	c.appendMsg("INBOX", "Subject: silent\r\n\r\nbody\r\n")
	c.do("SELECT INBOX")
	c.do(`UID STORE 1 FLAGS (\Seen)`)
	c.do("SELECT INBOX (CONDSTORE)")
	for _, command := range []string{`UID STORE 1 (UNCHANGEDSINCE 18446744073709551615) +FLAGS.SILENT (\Seen)`, `UID STORE 1 (UNCHANGEDSINCE 18446744073709551615) +FLAGS.SILENT (\Seen)`, `UID STORE 1 +FLAGS.SILENT (\Seen)`} {
		lines, _ := c.do(command)
		var fetches []string
		for _, line := range lines {
			if strings.Contains(line, " FETCH ") {
				fetches = append(fetches, line)
			}
		}
		require.Len(t, fetches, 1, "%s: %q", command, lines)
		require.Contains(t, fetches[0], "MODSEQ (")
		require.NotContains(t, fetches[0], "FLAGS (")
	}
}

func TestIMAP_StoreSilentMixedModifiedAndNoop(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	for range 2 {
		c.appendMsg("INBOX", "Subject: mixed\r\n\r\nbody\r\n")
	}
	c.do("SELECT INBOX (CONDSTORE)")
	c.do(`UID STORE 1:2 FLAGS (\Seen)`)
	ctx := context.Background()
	ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(ctx, owner.Email)
	require.NoError(t, err)
	mailbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, ownerID, "INBOX")
	require.NoError(t, err)
	var cutoff uint64
	require.NoError(t, server.ResilientDB.QueryRowWithRetry(ctx, `SELECT max(greatest(m.created_modseq,coalesce(ms.updated_modseq,0))) FROM messages m JOIN message_state ms ON ms.message_id=m.id AND ms.mailbox_id=m.mailbox_id WHERE m.mailbox_id=$1`, mailbox.ID).Scan(&cutoff))
	c.do(`UID STORE 1 +FLAGS (\Answered)`)
	c.do("SELECT INBOX (CONDSTORE)")
	for _, requested := range []string{`\Seen`, `\Flagged`} {
		lines, tagged := c.do(fmt.Sprintf(`UID STORE 1:2 (UNCHANGEDSINCE %d) +FLAGS.SILENT (%s)`, cutoff, requested))
		require.Contains(t, tagged, "MODIFIED 1")
		var success []string
		for _, line := range lines {
			if strings.Contains(line, " FETCH ") && strings.Contains(line, "UID 2") {
				success = append(success, line)
			}
		}
		require.Len(t, success, 1, "%q", lines)
		require.Contains(t, success[0], "MODSEQ (")
		if requested == `\Seen` {
			require.NotContains(t, success[0], "FLAGS (")
		}
	}
}
