package authcache

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

const (
	testNamespaceA = "11111111-1111-4111-8111-111111111111"
	testNamespaceB = "22222222-2222-4222-8222-222222222222"
)

func TestRevocationNamespaceCutoverWarmRestartAndDatabaseChange(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "auth.db")
	open := func() *Cache {
		t.Helper()
		c, err := New(path, time.Hour, 24*time.Hour, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	c := open()
	if err := c.Put(ctx, "before-tracking@example.com", 42, "revoked-before-feed-existed"); err != nil {
		t.Fatal(err)
	}
	c.Suspend()
	if err := c.EnsureRevocationNamespace(ctx, testNamespaceA); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	assertGenerationMiss(t, c, "before-tracking@example.com")
	if err := c.PutIfGeneration(ctx, "warm@example.com", 42, "current", c.Generation()); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c = open()
	c.Suspend()
	if err := c.EnsureRevocationNamespace(ctx, testNamespaceA); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if _, hash, err := c.Get(ctx, "warm@example.com"); err != nil || hash != "current" {
		t.Fatalf("same logical database lost warm synchronized entry: hash=%q err=%v", hash, err)
	}
	c.Suspend()
	if err := c.EnsureRevocationNamespace(ctx, testNamespaceB); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	assertGenerationMiss(t, c, "warm@example.com")
	if err := c.Put(ctx, "old-tracking-version@example.com", 43, "not-trusted"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.Exec(`UPDATE auth_cache_revocation SET tracking_version=68`); err != nil {
		t.Fatal(err)
	}
	c.Suspend()
	if err := c.EnsureRevocationNamespace(ctx, testNamespaceB); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	assertGenerationMiss(t, c, "old-tracking-version@example.com")
}

func TestRevocationNamespaceFailureRollsBackFlushAndMarker(t *testing.T) {
	c := generationTestCache(t)
	ctx := context.Background()
	c.Suspend()
	if err := c.EnsureRevocationNamespace(ctx, testNamespaceA); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, "old-database@example.com", 42, "old-hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.Exec(`CREATE TRIGGER refuse_namespace BEFORE UPDATE ON auth_cache_revocation
		BEGIN SELECT RAISE(ABORT, 'injected namespace persistence failure'); END`); err != nil {
		t.Fatal(err)
	}
	c.Suspend()
	if err := c.EnsureRevocationNamespace(ctx, testNamespaceB); err == nil {
		t.Fatal("injected marker update should fail")
	}
	assertGenerationMiss(t, c, "old-database@example.com")
	var rows int
	var namespace string
	if err := c.db.QueryRow(`SELECT COUNT(*) FROM auth_cache`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err := c.db.QueryRow(`SELECT database_uuid FROM auth_cache_revocation`).Scan(&namespace); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || namespace != testNamespaceA {
		t.Fatalf("failed transaction partially changed rows/marker: rows=%d old namespace retained=%v", rows, namespace == testNamespaceA)
	}
	if _, err := c.db.Exec(`DROP TRIGGER refuse_namespace`); err != nil {
		t.Fatal(err)
	}
	if err := c.EnsureRevocationNamespace(ctx, testNamespaceB); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	assertGenerationMiss(t, c, "old-database@example.com")
}

func TestRevocationNamespaceRequiresSuspensionAndValidIdentity(t *testing.T) {
	ctx := context.Background()
	c := generationTestCache(t)
	if err := c.Put(ctx, "old@example.com", 42, "old-hash"); err != nil {
		t.Fatal(err)
	}
	if err := c.EnsureRevocationNamespace(ctx, testNamespaceA); err == nil {
		t.Fatal("unsuspended namespace transition should fail")
	}
	assertGenerationMiss(t, c, "old@example.com")
	c.Suspend()
	for _, identity := range []string{"", "not-a-uuid", "00000000-0000-0000-0000-000000000000"} {
		if err := c.EnsureRevocationNamespace(ctx, identity); err == nil {
			t.Fatal("invalid identity should keep cache disabled")
		}
		assertGenerationMiss(t, c, "old@example.com")
	}
	if err := c.EnsureRevocationNamespace(ctx, testNamespaceA); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	assertGenerationMiss(t, c, "old@example.com")
}
