package pop3proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

func setupPOP3ProxyRevalidationDB(t *testing.T, address, initialPassword string) (*resilient.ResilientDatabase, int64) {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping database test in short mode")
	}

	ctx := context.Background()
	admin, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/postgres?sslmode=disable")
	if err != nil {
		t.Skipf("PostgreSQL not available on localhost:5432: %v", err)
	}
	defer admin.Close(ctx)

	base := os.Getenv("SORA_TEST_DB_NAME")
	if base == "" {
		base = "sora_test_db"
	}
	dbName := fmt.Sprintf("%s_pop3_reval_%d", base, time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		t.Fatalf("CREATE DATABASE %s: %v", dbName, err)
	}
	t.Cleanup(func() {
		cleanAdmin, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/postgres?sslmode=disable")
		if err != nil {
			t.Errorf("admin connect for cleanup: %v", err)
			return
		}
		defer cleanAdmin.Close(ctx)
		if _, err := cleanAdmin.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Errorf("DROP DATABASE %s: %v", dbName, err)
		}
	})

	cfg := &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{
			Hosts: []string{"localhost"},
			Port:  "5432",
			User:  "postgres",
			Name:  dbName,
		},
	}
	rdb, err := resilient.NewResilientDatabaseWithOptions(ctx, cfg, false, true, true)
	if err != nil {
		t.Fatalf("NewResilientDatabaseWithOptions: %v", err)
	}
	t.Cleanup(rdb.Close)

	hash, err := db.GenerateSSHA512Hash(initialPassword)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	var accountID int64
	if err := rdb.GetOperationalDatabase().GetWritePool().QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&accountID); err != nil {
		t.Fatalf("insert account: %v", err)
	}
	if _, err := rdb.GetOperationalDatabase().GetWritePool().Exec(ctx,
		`INSERT INTO credentials (account_id, address, password, primary_identity) VALUES ($1, $2, $3, true)`,
		accountID, address, hash,
	); err != nil {
		t.Fatalf("insert credential: %v", err)
	}

	return rdb, accountID
}

func startAcceptingPOP3Backend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.WriteString(c, "+OK backend ready\r\n")
				_, _ = bufio.NewReader(c).ReadString('\n')
				_, _ = io.WriteString(c, "+OK logged in\r\n")
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// TestPOP3ProxyRevalidationRefreshesCacheGeneration verifies that when a positive
// lookupCache entry is invalidated for revalidation ("password differs from cached login"),
// authenticate refreshes cacheGeneration afterwards so SetIfGeneration does not self-fence
// and drop the revalidated positive or negative cache fill.
func TestPOP3ProxyRevalidationRefreshesCacheGeneration(t *testing.T) {
	const address = "reval-pop3@example.com"
	rdb, accountID := setupPOP3ProxyRevalidationDB(t, address, "old-password")
	backendAddr := startAcceptingPOP3Backend(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := &POP3ProxyServer{
		name:                       "pop3-reval-gen",
		hostname:                   "test-host",
		appCtx:                     ctx,
		cancel:                     cancel,
		connManager:                newPOP3TestConnManager(t, backendAddr, 2*time.Second),
		lookupCache:                newPOP3TestLookupCache(t),
		authLimiter:                (*server.AuthRateLimiter)(nil),
		positiveRevalidationWindow: 30 * time.Second,
		activeSessions:             make(map[*POP3ProxySession]struct{}),
		masterUsername:             "admin",
		masterPassword:             "master-secret",
		rdb:                        rdb,
	}

	login := func(username, password string) error {
		client, remote := net.Pipe()
		defer client.Close()
		defer remote.Close()
		sessCtx, sessCancel := context.WithCancel(ctx)
		defer sessCancel()
		sess := &POP3ProxySession{server: srv, clientConn: client, listenerConn: client, ctx: sessCtx, cancel: sessCancel}
		err := sess.authenticate(username, password)
		if sess.backendConn != nil {
			_ = sess.backendConn.Close()
		}
		return err
	}

	// Update password in DB to "new-password".
	newHash, err := db.GenerateSSHA512Hash("new-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := rdb.GetOperationalDatabase().GetWritePool().Exec(ctx,
		`UPDATE credentials SET password = $1, updated_at = now() WHERE account_id = $2`,
		newHash, accountID,
	); err != nil {
		t.Fatalf("update password: %v", err)
	}

	t.Run("valid new password populates positive cache entry", func(t *testing.T) {
		now := time.Now()
		srv.lookupCache.Set(srv.name, address, &lookupcache.CacheEntry{
			AccountID:      accountID,
			PasswordDigest: lookupcache.NewPasswordDigest("old-password"),
			Result:         lookupcache.AuthSuccess,
			CreatedAt:      now.Add(-time.Minute),
			ExpiresAt:      now.Add(time.Minute),
		})

		if err := login(address, "new-password"); err != nil {
			t.Fatalf("authenticate with new password failed: %v", err)
		}

		cached, found := srv.lookupCache.Get(srv.name, address)
		if !found {
			t.Fatal("revalidated login dropped its lookupCache fill (SetIfGeneration self-fenced)")
		}
		if cached.IsNegative || cached.Result != lookupcache.AuthSuccess {
			t.Fatalf("expected positive AuthSuccess entry, got %+v", cached)
		}
		if !cached.PasswordDigest.Matches("new-password") {
			t.Fatal("cached entry does not carry the new password digest")
		}
	})

	t.Run("wrong password populates negative cache entry", func(t *testing.T) {
		now := time.Now()
		srv.lookupCache.Set(srv.name, address, &lookupcache.CacheEntry{
			AccountID:      accountID,
			PasswordDigest: lookupcache.NewPasswordDigest("old-password"),
			Result:         lookupcache.AuthSuccess,
			CreatedAt:      now.Add(-time.Minute),
			ExpiresAt:      now.Add(time.Minute),
		})

		if err := login(address, "wrong-password"); !errors.Is(err, consts.ErrAuthenticationFailed) {
			t.Fatalf("authenticate with wrong password: got %v, want %v", err, consts.ErrAuthenticationFailed)
		}

		cached, found := srv.lookupCache.Get(srv.name, address)
		if !found {
			t.Fatal("revalidated failed login dropped its negative lookupCache fill (SetIfGeneration self-fenced)")
		}
		if !cached.IsNegative || !cached.PasswordDigest.Matches("wrong-password") {
			t.Fatalf("expected negative cache entry for wrong-password, got %+v", cached)
		}
	})

	t.Run("master form credential switch populates cache within window", func(t *testing.T) {
		const masterSubmitted = address + "@admin"
		now := time.Now()
		srv.lookupCache.Set(srv.name, masterSubmitted, &lookupcache.CacheEntry{
			AccountID:      accountID,
			PasswordDigest: lookupcache.NewPasswordDigest("master-secret"),
			Result:         lookupcache.AuthSuccess,
			CreatedAt:      now,
			ExpiresAt:      now.Add(time.Minute),
		})

		if err := login(masterSubmitted, "new-password"); err != nil {
			t.Fatalf("authenticate with account password on master form failed: %v", err)
		}

		cached, found := srv.lookupCache.Get(srv.name, masterSubmitted)
		if !found || cached.IsNegative || !cached.PasswordDigest.Matches("new-password") {
			t.Fatalf("expected cached positive entry for switched master-form password, got found=%v entry=%+v", found, cached)
		}
	})
}
