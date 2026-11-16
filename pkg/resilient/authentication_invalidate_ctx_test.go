package resilient

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/authcache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/server"
	"golang.org/x/crypto/bcrypt"
)

// expiringAuthContext models a caller request context (such as a proxy authTimeout)
// that is still live when Step 1 reads SQLite, then expires while CPU-bound bcrypt
// verifies the password against the cached hash.
type expiringAuthContext struct {
	context.Context
	done chan struct{}
	once sync.Once
	err  atomic.Value
}

func newExpiringAuthContext(parent context.Context) *expiringAuthContext {
	return &expiringAuthContext{
		Context: parent,
		done:    make(chan struct{}),
	}
}

func (c *expiringAuthContext) Done() <-chan struct{} { return c.done }

func (c *expiringAuthContext) Err() error {
	if v := c.err.Load(); v != nil {
		return v.(error)
	}
	return c.Context.Err()
}

func (c *expiringAuthContext) expire(err error) {
	c.once.Do(func() {
		c.err.Store(err)
		close(c.done)
	})
}

type expireOnGetAuthCache struct {
	*authcache.Cache
	target   string
	afterGet func()
}

func (c *expireOnGetAuthCache) Get(ctx context.Context, address string) (int64, string, error) {
	id, hash, err := c.Cache.Get(ctx, address)
	if err == nil && address == c.target && c.afterGet != nil {
		c.afterGet()
	}
	return id, hash, err
}

func newClosedPortResilientDB(t *testing.T) *ResilientDatabase {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ephemeral port: %v", err)
	}
	addr := ln.Addr().String()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("split host port: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close ephemeral listener: %v", err)
	}

	cfg := &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{
			Hosts: []string{host},
			Port:  port,
			User:  "postgres",
			Name:  "unused_closed_port_db",
		},
	}
	poolCfg, err := pgxpool.ParseConfig(fmt.Sprintf("postgres://postgres@%s/unused_closed_port_db?sslmode=disable", addr))
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	t.Cleanup(pool.Close)

	dbPool := &DatabasePool{
		database: &db.Database{WritePool: pool, ReadPool: pool},
		host:     host,
	}
	dbPool.isHealthy.Store(true)
	return &ResilientDatabase{
		failoverManager: &RuntimeFailoverManager{
			writePools:      []*DatabasePool{dbPool},
			readPools:       []*DatabasePool{dbPool},
			config:          cfg,
			healthCheckStop: make(chan struct{}),
		},
		queryBreaker: circuitbreaker.NewCircuitBreaker(circuitbreaker.DefaultSettings("test_auth_invalidate_query")),
		writeBreaker: circuitbreaker.NewCircuitBreaker(circuitbreaker.DefaultSettings("test_auth_invalidate_write")),
		config:       cfg,
	}
}

func authCacheRowCount(t *testing.T, sqliteDB *sql.DB, address string) int {
	t.Helper()
	var count int
	if err := sqliteDB.QueryRow(`SELECT COUNT(*) FROM auth_cache WHERE address = ?`, address).Scan(&count); err != nil {
		t.Fatalf("query auth_cache row count for %s: %v", address, err)
	}
	return count
}

// TestAuthenticateWithRetry_ExpiredCallerContextDuringMismatchDoesNotPoisonAuthCache
// proves that when a caller context expires or cancels while CPU-bound db.VerifyPassword
// runs on a wrong/changed password against a cached hash, Step 1's mismatch invalidation
// still deletes the target entry using a bounded background context instead of passing the
// expired caller ctx to authCache.Invalidate — which would abort the SQLite DELETE, mark
// authCache unhealthy for all users node-wide, and cause the next Resume tick to wipe
// every unrelated user's cached credentials from SQLite.
func TestAuthenticateWithRetry_ExpiredCallerContextDuringMismatchDoesNotPoisonAuthCache(t *testing.T) {
	victimBytes, err := bcrypt.GenerateFromPassword([]byte("victim-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash victim password: %v", err)
	}
	targetBytes, err := bcrypt.GenerateFromPassword([]byte("target-real-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash target password: %v", err)
	}
	victimHash := string(victimBytes)
	targetHash := string(targetBytes)

	const (
		victimAddr = "victim@example.com"
		victimID   = int64(101)
		targetAddr = "target@example.com"
		targetID   = int64(202)
	)

	cases := []struct {
		name       string
		makeCtx    func(parent context.Context) (authCtx context.Context, expire func())
		wantCtxErr error
	}{
		{
			name: "deadline_exceeded_during_verify",
			makeCtx: func(parent context.Context) (context.Context, func()) {
				c := newExpiringAuthContext(parent)
				return c, func() { c.expire(context.DeadlineExceeded) }
			},
			wantCtxErr: context.DeadlineExceeded,
		},
		{
			name: "caller_canceled_during_verify",
			makeCtx: func(parent context.Context) (context.Context, func()) {
				return context.WithCancel(parent)
			},
			wantCtxErr: context.Canceled,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bg := context.Background()
			dbPath := filepath.Join(t.TempDir(), "auth_cache.db")
			persistent, err := authcache.New(dbPath, time.Hour, 24*time.Hour, time.Hour)
			if err != nil {
				t.Fatalf("open auth cache: %v", err)
			}
			t.Cleanup(func() {
				if closeErr := persistent.Close(); closeErr != nil {
					t.Errorf("close auth cache: %v", closeErr)
				}
			})

			inspector, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)")
			if err != nil {
				t.Fatalf("open sqlite inspector: %v", err)
			}
			t.Cleanup(func() { _ = inspector.Close() })

			if err := persistent.Put(bg, victimAddr, victimID, victimHash); err != nil {
				t.Fatalf("seed victim cache entry: %v", err)
			}
			if err := persistent.Put(bg, targetAddr, targetID, targetHash); err != nil {
				t.Fatalf("seed target cache entry: %v", err)
			}
			if gotID, gotHash, err := persistent.Get(bg, victimAddr); err != nil || gotID != victimID || gotHash != victimHash {
				t.Fatalf("precondition victim cache hit failed: id=%d err=%v", gotID, err)
			}
			if gotID, gotHash, err := persistent.Get(bg, targetAddr); err != nil || gotID != targetID || gotHash != targetHash {
				t.Fatalf("precondition target cache hit failed: id=%d err=%v", gotID, err)
			}

			authCtx, expire := tc.makeCtx(bg)
			defer expire()

			rd := newClosedPortResilientDB(t)
			rd.SetAuthCache(&expireOnGetAuthCache{
				Cache:    persistent,
				target:   targetAddr,
				afterGet: expire,
			})

			_, authErr := rd.AuthenticateWithRetry(authCtx, targetAddr, "wrong-password")
			if !errors.Is(authErr, server.ErrAuthServiceUnavailable) || !errors.Is(authErr, tc.wantCtxErr) {
				t.Fatalf("AuthenticateWithRetry error = %v, want wrapping %v and %v", authErr, server.ErrAuthServiceUnavailable, tc.wantCtxErr)
			}

			// 1. target@example.com's mismatched entry must be deleted from SQLite even though
			// the caller's request context expired while VerifyPassword was running.
			if rows := authCacheRowCount(t, inspector, targetAddr); rows != 0 {
				t.Errorf("stale %s row remained in SQLite after mismatch invalidation: got %d rows, want 0", targetAddr, rows)
			}

			// 2. Unrelated victim@example.com must still hit in authCache (must NOT be poisoned
			// with unhealthy=true).
			if gotID, gotHash, err := persistent.Get(bg, victimAddr); err != nil || gotID != victimID || gotHash != victimHash {
				t.Errorf("unrelated %s cache lookup failed after %s mismatch: id=%d err=%v (want id=%d nil)",
					victimAddr, targetAddr, gotID, err, victimID)
			}

			// 3. The next credchanges.Watcher Resume tick must NOT wipe victim@example.com from SQLite.
			if err := persistent.Resume(bg); err != nil {
				t.Fatalf("Resume: %v", err)
			}
			if rows := authCacheRowCount(t, inspector, victimAddr); rows != 1 {
				t.Errorf("Resume wiped unrelated %s from SQLite: got %d rows, want 1", victimAddr, rows)
			}
			if gotID, gotHash, err := persistent.Get(bg, victimAddr); err != nil || gotID != victimID || gotHash != victimHash {
				t.Errorf("unrelated %s cache lookup failed after Resume: id=%d err=%v (want id=%d nil)",
					victimAddr, gotID, err, victimID)
			}
		})
	}
}
