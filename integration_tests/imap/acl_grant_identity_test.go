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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	serverimap "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/require"
)

type aclPermissionGateKey struct{}

// Pause after the real permission query finishes, before SETACL continues. This
// affects only this server's pool and this delegate/mailbox, without changing SQL
// functions or blocking other tests that share the database.
type aclPermissionGate struct {
	mailboxID, accountID int64
	reached, release     chan struct{}
	paused               atomic.Bool
	resumeOnce           sync.Once
	// inTransaction pauses at the 'a' re-check inside the ACL write transaction,
	// with the ACL lock held, instead of at SETACL's own check before it.
	inTransaction bool
}

func (g *aclPermissionGate) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !strings.Contains(data.SQL, "SELECT has_mailbox_right(") || len(data.Args) < 2 ||
		data.Args[0] != g.mailboxID || data.Args[1] != g.accountID {
		return ctx
	}
	if g.inTransaction && len(data.Args) == 2 || !g.inTransaction && len(data.Args) == 3 && data.Args[2] == "a" {
		return context.WithValue(ctx, aclPermissionGateKey{}, true)
	}
	return ctx
}

func (g *aclPermissionGate) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if ctx.Value(aclPermissionGateKey{}) != true || data.Err != nil || !g.paused.CompareAndSwap(false, true) {
		return
	}
	close(g.reached)
	select {
	case <-g.release:
	case <-ctx.Done():
	}
}

func (g *aclPermissionGate) resume() { g.resumeOnce.Do(func() { close(g.release) }) }

func startACLPermissionGateServer(t *testing.T, source *resilient.ResilientDatabase, gate *aclPermissionGate) string {
	t.Helper()
	ctx := context.Background()
	connCfg := source.GetDatabase().GetWritePool().Config().ConnConfig
	rdb, err := resilient.NewResilientDatabase(ctx, &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{
			Hosts: []string{connCfg.Host}, Port: fmt.Sprint(connCfg.Port), User: connCfg.User,
			Password: connCfg.Password, Name: connCfg.Database,
		},
	}, false, false)
	require.NoError(t, err)
	t.Cleanup(rdb.Close)

	// Install the tracer before starting any server or health-check goroutines.
	database := rdb.GetDatabase()
	oldPool := database.GetWritePool()
	poolCfg := oldPool.Config().Copy()
	poolCfg.ConnConfig.Tracer = gate
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	require.NoError(t, err)
	database.WritePool, database.ReadPool = pool, pool
	oldPool.Close()

	address := common.GetRandomAddress(t)
	srv, err := serverimap.New(ctx, "test-acl-identity", "localhost", address,
		&storage.S3Storage{}, rdb, nil, nil, serverimap.IMAPServerOptions{
			InsecureAuth: true,
			Config: &config.Config{SharedMailboxes: config.SharedMailboxesConfig{
				Enabled: true, NamespacePrefix: "Shared/", AllowUserCreate: true, AllowAnyoneIdentifier: true,
			}},
		})
	require.NoError(t, err)
	go func() { _ = srv.Serve(address) }()
	t.Cleanup(func() { srv.Close() })
	require.Eventually(t, func() bool {
		c, err := imapclient.DialInsecure(address, nil)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond)
	return address
}

func TestACL_DelegatedGrantKeepsMailboxIdentity(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	for _, replace := range []bool{false, true} {
		for _, anyone := range []bool{false, true} {
			t.Run(fmt.Sprintf("recreate=%t/anyone=%t", replace, anyone), func(t *testing.T) {
				ctx := context.Background()
				server, owner := common.SetupIMAPServer(t)
				defer server.Close()
				admin, password := createSecondUser(t, server, "example.com", "identity")
				ownerID, err := server.ResilientDB.GetActiveAccountIDByAddressWithRetry(ctx, owner.Email)
				require.NoError(t, err)
				adminID, err := server.ResilientDB.GetActiveAccountIDByAddressWithRetry(ctx, admin)
				require.NoError(t, err)
				co, err := imapclient.DialInsecure(server.Address, nil)
				require.NoError(t, err)
				defer co.Close()
				require.NoError(t, co.Login(owner.Email, owner.Password).Wait())
				prefix := fmt.Sprintf("Shared/Identity-%d-", common.GetTimestamp())
				target, secret, archived := prefix+"Delegated", prefix+"Confidential", prefix+"Archived"
				defer func() {
					for _, name := range []string{target, secret, archived} {
						co.Delete(name).Wait()
					}
				}()
				require.NoError(t, co.Create(target, nil).Wait())
				require.NoError(t, co.Create(secret, nil).Wait())
				require.NoError(t, co.SetACL(target, imap.RightsIdentifier(admin), imap.RightModificationReplace, imap.RightSet("lra")).Wait())
				authorized, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, ownerID, target)
				require.NoError(t, err)
				gate := &aclPermissionGate{mailboxID: authorized.ID, accountID: adminID, reached: make(chan struct{}), release: make(chan struct{})}
				address := startACLPermissionGateServer(t, server.ResilientDB, gate)
				ca, err := imapclient.DialInsecure(address, nil)
				require.NoError(t, err)
				defer ca.Close()
				defer gate.resume()
				require.NoError(t, ca.Login(admin, password).Wait())
				identifier, rights := imap.RightsIdentifier(admin), imap.RightSet(db.AllACLRights)
				if anyone {
					identifier, rights = "anyone", imap.RightSet("lr")
				}
				result := make(chan error, 1)
				go func() { result <- ca.SetACL(target, identifier, imap.RightModificationReplace, rights).Wait() }()
				select {
				case <-gate.reached:
				case <-time.After(5 * time.Second):
					t.Fatal("SETACL never reached the permission check")
				}
				if replace {
					require.NoError(t, co.Delete(target).Wait())
					require.NoError(t, co.Create(target, nil).Wait())
				} else {
					require.NoError(t, co.Rename(target, archived, nil).Wait())
					require.NoError(t, co.Rename(secret, target, nil).Wait())
				}
				gate.resume()
				var commandErr error
				select {
				case err := <-result:
					commandErr = err
				case <-time.After(5 * time.Second):
					t.Fatal("SETACL did not finish after releasing the permission check")
				}
				acl, err := co.GetACL(target).Wait()
				require.NoError(t, err)
				require.NotContains(t, acl.Rights, identifier, "replacement mailbox must not receive the grant")
				if replace {
					requireResponseCode(t, commandErr, imap.ResponseCodeNonExistent, "SETACL on the deleted mailbox")
				} else {
					require.NoError(t, commandErr)
					acl, err := co.GetACL(archived).Wait()
					require.NoError(t, err)
					// The wire layer may also return the obsolete virtual c/d rights.
					require.True(t, hasAllRights(acl.Rights[identifier], rights), "grant must follow the authorized mailbox")
				}
			})
		}
	}
}
