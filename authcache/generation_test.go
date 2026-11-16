package authcache

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func generationTestCache(t *testing.T) *Cache {
	t.Helper()
	c, err := New(filepath.Join(t.TempDir(), "auth.db"), time.Hour, 24*time.Hour, time.Hour)
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

func assertGenerationMiss(t *testing.T, c *Cache, address string) {
	t.Helper()
	if _, _, err := c.Get(context.Background(), address); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("Get(%q) = %v, want cache miss", address, err)
	}
}

func TestGenerationRejectsPreInvalidationFill(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		invalidate func(*Cache) error
	}{
		{"address", func(c *Cache) error { return c.Invalidate(ctx, "alice@example.com") }},
		{"account", func(c *Cache) error { return c.InvalidateAccount(ctx, 42) }},
		{"batch", func(c *Cache) error { return c.InvalidateAccounts(ctx, []int64{42, 43}) }},
		{"all", func(c *Cache) error { return c.InvalidateAll(ctx) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := generationTestCache(t)
			beforeRead := c.Generation()
			if err := tc.invalidate(c); err != nil {
				t.Fatal(err)
			}
			if err := c.PutIfGeneration(ctx, "alice@example.com", 42, "old-hash", beforeRead); err != nil {
				t.Fatal(err)
			}
			assertGenerationMiss(t, c, "alice@example.com")
			if err := c.PutIfGeneration(ctx, "alice@example.com", 42, "new-hash", c.Generation()); err != nil {
				t.Fatal(err)
			}
			id, hash, err := c.Get(ctx, "alice@example.com")
			if err != nil || id != 42 || hash != "new-hash" {
				t.Fatalf("fresh fill: id=%d hash=%q err=%v", id, hash, err)
			}
		})
	}
}

func TestGenerationSuspensionFencesLookupAcrossResume(t *testing.T) {
	c := generationTestCache(t)
	ctx := context.Background()
	if err := c.Put(ctx, "persisted@example.com", 42, "still-current"); err != nil {
		t.Fatal(err)
	}
	c.Suspend()
	beforeRead := c.Generation()
	assertGenerationMiss(t, c, "persisted@example.com")
	if err := c.PutIfGeneration(ctx, "during@example.com", 43, "ignored", beforeRead); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.PutIfGeneration(ctx, "late@example.com", 43, "ignored", beforeRead); err != nil {
		t.Fatal(err)
	}
	assertGenerationMiss(t, c, "during@example.com")
	assertGenerationMiss(t, c, "late@example.com")
	if _, hash, err := c.Get(ctx, "persisted@example.com"); err != nil || hash != "still-current" {
		t.Fatalf("synchronized unchanged persisted entry: hash=%q err=%v", hash, err)
	}
}

func TestInvalidationFailureQuarantinesUntilFullFlush(t *testing.T) {
	c := generationTestCache(t)
	ctx := context.Background()
	for address, id := range map[string]int64{"failed@example.com": 42, "other@example.com": 43} {
		if err := c.Put(ctx, address, id, "old-hash"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.db.Exec(`CREATE TRIGGER refuse_revocation BEFORE DELETE ON auth_cache
		WHEN OLD.account_id = 42 BEGIN SELECT RAISE(ABORT, 'injected revocation failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := c.InvalidateAccount(ctx, 42); err == nil {
		t.Fatal("injected invalidation should fail")
	}
	assertGenerationMiss(t, c, "failed@example.com")
	assertGenerationMiss(t, c, "other@example.com")
	if err := c.PutIfGeneration(ctx, "new@example.com", 44, "ignored", c.Generation()); err != nil {
		t.Fatal(err)
	}
	assertGenerationMiss(t, c, "new@example.com")
	// A successful deletion of B cannot rehabilitate the stale row left for A.
	if err := c.InvalidateAccount(ctx, 43); err != nil {
		t.Fatal(err)
	}
	assertGenerationMiss(t, c, "failed@example.com")
	if err := c.Resume(ctx); err == nil {
		t.Fatal("full flush must still fail while A's DELETE is refused")
	}
	assertGenerationMiss(t, c, "failed@example.com")
	if _, err := c.db.Exec(`DROP TRIGGER refuse_revocation`); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	assertGenerationMiss(t, c, "failed@example.com")
	assertGenerationMiss(t, c, "other@example.com")
	if err := c.PutIfGeneration(ctx, "new@example.com", 44, "fresh", c.Generation()); err != nil {
		t.Fatal(err)
	}
	if _, hash, err := c.Get(ctx, "new@example.com"); err != nil || hash != "fresh" {
		t.Fatalf("healthy fill after full flush: hash=%q err=%v", hash, err)
	}
}
