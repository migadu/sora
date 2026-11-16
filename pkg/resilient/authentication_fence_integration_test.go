//go:build integration

package resilient

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/authcache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"golang.org/x/crypto/bcrypt"
)

func authFenceDatabase(t *testing.T, suffix string) (*config.DatabaseConfig, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/postgres?sslmode=disable")
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	defer admin.Close(ctx)
	name := fmt.Sprintf("sora_authfence_%d_%s", time.Now().UnixNano(), suffix)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg := &config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
		Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name,
	}}
	t.Cleanup(func() {
		admin, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/postgres?sslmode=disable")
		if err != nil {
			t.Error(err)
			return
		}
		defer admin.Close(ctx)
		if _, err := admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error(err)
		}
	})
	database, err := db.NewDatabaseFromConfig(ctx, cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	database.Close()
	pool := authFencePool(t, name, nil)
	return cfg, pool
}

func authFencePool(t *testing.T, name string, tracer pgx.QueryTracer) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://postgres@localhost:5432/" + name + "?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func authFenceCredential(t *testing.T, pool *pgxpool.Pool, address, hash string) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	if err := pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO credentials (account_id,address,password,primary_identity)
		VALUES ($1,$2,$3,true)`, id, address, hash); err != nil {
		t.Fatal(err)
	}
	return id
}

func authFenceHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), db.BcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(hash)
}

func authFenceCache(t *testing.T) *authcache.Cache {
	t.Helper()
	c, err := authcache.New(filepath.Join(t.TempDir(), "credentials.db"), time.Hour, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return c
}

// The two independent databases model a primary and a replica that remains stale
// beyond any former one-minute invalidation overlap. No sleeps simulate catch-up.
func TestAuthCacheDoesNotRefillFromStaleReplica(t *testing.T) {
	ctx := context.Background()
	cfg, primary := authFenceDatabase(t, "primary")
	_, replica := authFenceDatabase(t, "replica")
	const address = "stale-replica@example.com"
	oldHash, newHash := authFenceHash(t, "old-test-password"), authFenceHash(t, "new-test-password")
	id := authFenceCredential(t, primary, address, oldHash)
	if replicaID := authFenceCredential(t, replica, address, oldHash); replicaID != id {
		t.Fatal("fixture requires equal numeric account IDs")
	}
	if _, err := primary.Exec(ctx, `UPDATE credentials SET password=$1,updated_at='2026-11-16 12:00:00+00' WHERE account_id=$2`, newHash, id); err != nil {
		t.Fatal(err)
	}
	if _, err := replica.Exec(ctx, `UPDATE credentials SET updated_at='2025-11-16 12:00:00+00' WHERE account_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	rd := newTestResilientDatabase(cfg, primary)
	// Catch both layers of routing: selecting the primary Database object is
	// insufficient if that object's internal read pool still names the replica.
	rd.failoverManager.writePools[0].database.ReadPool = replica
	rp := &DatabasePool{database: &db.Database{WritePool: replica, ReadPool: replica}, host: "replica"}
	rp.isHealthy.Store(true)
	rd.failoverManager.readPools = []*DatabasePool{rp}
	cache := authFenceCache(t)
	rd.SetAuthCache(cache)
	if err := cache.Put(ctx, address, id, oldHash); err != nil {
		t.Fatal(err)
	}
	if err := cache.InvalidateAccount(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := rd.AuthenticateWithRetry(ctx, address, "old-test-password"); !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		t.Fatalf("old replica password accepted or misclassified: %v", err)
	}
	if got, err := rd.AuthenticateWithRetry(ctx, address, "new-test-password"); err != nil || got != id {
		t.Fatalf("new primary password: id=%d err=%v", got, err)
	}
	if _, hash, err := rd.GetCredentialForAuthWithRetry(ctx, address); err != nil || hash != newHash {
		t.Fatalf("backend credential did not use primary: err=%v", err)
	}
	_, tokenHash, epoch, err := rd.GetCredentialForTokenWithRetry(ctx, address)
	if err != nil || tokenHash != newHash || epoch.Year() != 2026 {
		t.Fatalf("token credential did not use primary: epoch=%v err=%v", epoch, err)
	}
	if _, epoch, err := rd.GetCredentialEpochWithRetry(ctx, address); err != nil || epoch.Year() != 2026 {
		t.Fatalf("refresh epoch did not use primary: epoch=%v err=%v", epoch, err)
	}
	// The replica is deliberately still live with the old password/account.
	if _, hash, err := rp.database.GetCredentialForAuth(ctx, address); err != nil || hash != oldHash {
		t.Fatal("stale-replica control was not actually stale")
	}
	if _, err := primary.Exec(ctx, `UPDATE accounts SET deleted_at=now() WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err := cache.InvalidateAccount(ctx, id); err != nil {
		t.Fatal(err)
	}
	for name, lookup := range map[string]func() error{
		"backend":       func() error { _, _, err := rd.GetCredentialForAuthWithRetry(ctx, address); return err },
		"token":         func() error { _, _, _, err := rd.GetCredentialForTokenWithRetry(ctx, address); return err },
		"refresh":       func() error { _, _, err := rd.GetCredentialEpochWithRetry(ctx, address); return err },
		"master target": func() error { _, err := rd.GetMasterLoginTargetWithRetry(ctx, address); return err },
	} {
		if err := lookup(); !errors.Is(err, consts.ErrUserNotFound) {
			t.Errorf("%s accepted a primary-deleted account or misclassified it: %v", name, err)
		}
	}
}

type authReadGateKey struct{}
type authReadGate struct {
	armed   atomic.Bool
	read    chan struct{}
	release chan struct{}
}

func (g *authReadGate) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "SELECT c.account_id, c.password") && g.armed.CompareAndSwap(true, false) {
		return context.WithValue(ctx, authReadGateKey{}, true)
	}
	return ctx
}

func (g *authReadGate) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	if ctx.Value(authReadGateKey{}) == true {
		close(g.read)
		select {
		case <-g.release:
		case <-ctx.Done():
		}
	}
}

type observedAuthFill struct {
	*authcache.Cache
	filled chan struct{}
	once   sync.Once
}

func (c *observedAuthFill) Put(ctx context.Context, address string, id int64, hash string) error {
	err := c.Cache.Put(ctx, address, id, hash)
	c.once.Do(func() { close(c.filled) })
	return err
}

func (c *observedAuthFill) PutIfGeneration(ctx context.Context, address string, id int64, hash string, generation uint64) error {
	err := c.Cache.PutIfGeneration(ctx, address, id, hash, generation)
	c.once.Do(func() { close(c.filled) })
	return err
}

func TestAuthCacheInvalidationDuringPrimaryReadFencesLateFill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cfg, control := authFenceDatabase(t, "inflight")
	const address = "inflight-primary@example.com"
	oldHash := authFenceHash(t, "old-test-password")
	id := authFenceCredential(t, control, address, oldHash)
	gate := &authReadGate{read: make(chan struct{}), release: make(chan struct{})}
	gate.armed.Store(true)
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(gate.release) })
	primary := authFencePool(t, cfg.Write.Name, gate)
	rd := newTestResilientDatabase(cfg, primary)
	cache := &observedAuthFill{Cache: authFenceCache(t), filled: make(chan struct{})}
	rd.SetAuthCache(cache)
	done := make(chan error, 1)
	go func() {
		_, err := rd.AuthenticateWithRetry(ctx, address, "old-test-password")
		done <- err
	}()
	select {
	case <-gate.read:
	case <-ctx.Done():
		t.Fatal("credential read did not reach the primary result barrier")
	}
	newHash := authFenceHash(t, "new-test-password")
	if _, err := control.Exec(ctx, `UPDATE credentials SET password=$1 WHERE account_id=$2`, newHash, id); err != nil {
		t.Fatal(err)
	}
	if err := cache.InvalidateAccount(ctx, id); err != nil {
		t.Fatal(err)
	}
	releaseOnce.Do(func() { close(gate.release) })
	// The already-started auth may finish using the read it made before the
	// reset, but it must not repopulate credentials for any later request.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("overlapping original authentication: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("overlapping authentication did not finish")
	}
	select {
	case <-cache.filled:
	case <-ctx.Done():
		t.Fatal("asynchronous cache fill did not finish")
	}
	if _, _, err := cache.Get(ctx, address); !errors.Is(err, authcache.ErrCacheMiss) {
		t.Fatalf("late primary result refilled the revoked cache: %v", err)
	}
	if _, err := rd.AuthenticateWithRetry(ctx, address, "old-test-password"); !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		t.Fatalf("subsequent revoked password accepted or misclassified: %v", err)
	}
}

func TestAuthRehashDoesNotOverwriteCredentialReset(t *testing.T) {
	ctx := context.Background()
	cfg, pool := authFenceDatabase(t, "rehash")
	const address = "rehash-reset@example.com"
	id := authFenceCredential(t, pool, address, "initial-hash")
	rd := newTestResilientDatabase(cfg, pool)
	if changed, err := rd.RehashCredentialWithRetry(ctx, address, id, "initial-hash", "rehash-hash"); err != nil || !changed {
		t.Fatalf("matching rehash: changed=%v err=%v", changed, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE credentials SET password='user-reset-hash' WHERE account_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if changed, err := rd.RehashCredentialWithRetry(ctx, address, id, "rehash-hash", "stale-rehash-hash"); err != nil || changed {
		t.Fatalf("stale rehash overwrote a reset: changed=%v err=%v", changed, err)
	}
	var hash string
	if err := pool.QueryRow(ctx, `SELECT password FROM credentials WHERE account_id=$1`, id).Scan(&hash); err != nil || hash != "user-reset-hash" {
		t.Fatalf("reset credential changed: err=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE accounts SET deleted_at=now() WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if changed, err := rd.RehashCredentialWithRetry(ctx, address, id, "user-reset-hash", "deleted-rehash-hash"); err != nil || changed {
		t.Fatalf("rehash changed deleted account: changed=%v err=%v", changed, err)
	}
}
