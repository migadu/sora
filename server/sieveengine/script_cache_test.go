package sieveengine

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

const cachedScript = `require "fileinto";
fileinto "Archive";
`

const editedScript = `require "fileinto";
fileinto "Later";
`

func TestScriptCacheReusesCompiledScript(t *testing.T) {
	cache := NewScriptCache(10, time.Minute)

	first, err := cache.GetOrCompile(cachedScript, DefaultSieveExtensions)
	if err != nil {
		t.Fatalf("GetOrCompile: %v", err)
	}
	second, err := cache.GetOrCompile(cachedScript, DefaultSieveExtensions)
	if err != nil {
		t.Fatalf("GetOrCompile (second): %v", err)
	}
	if first != second {
		t.Errorf("same script must not be recompiled")
	}
	if hits, misses := cache.Stats(); hits != 1 || misses != 1 {
		t.Errorf("Stats() = (%d hits, %d misses), want (1, 1)", hits, misses)
	}
}

func TestScriptCacheInvalidation(t *testing.T) {
	t.Run("edited script recompiles", func(t *testing.T) {
		cache := NewScriptCache(10, time.Minute)
		first, err := cache.GetOrCompile(cachedScript, DefaultSieveExtensions)
		if err != nil {
			t.Fatalf("GetOrCompile: %v", err)
		}
		second, err := cache.GetOrCompile(editedScript, DefaultSieveExtensions)
		if err != nil {
			t.Fatalf("GetOrCompile (edited): %v", err)
		}
		if first == second {
			t.Fatalf("an updated script must be recompiled, not served from cache")
		}
		// The new copy, not the old one, is what subsequent deliveries evaluate.
		got, err := evaluateFileintoTarget(second)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if got != "Later" {
			t.Errorf("cached script filed into %q, want Later", got)
		}
	})

	t.Run("different extension set is a different entry", func(t *testing.T) {
		cache := NewScriptCache(10, time.Minute)
		first, err := cache.GetOrCompile(cachedScript, DefaultSieveExtensions)
		if err != nil {
			t.Fatalf("GetOrCompile: %v", err)
		}
		second, err := cache.GetOrCompile(cachedScript, []string{"fileinto"})
		if err != nil {
			t.Fatalf("GetOrCompile (other extensions): %v", err)
		}
		if first == second {
			t.Errorf("a different extension set must compile its own script")
		}
	})

	t.Run("entry expires after the ttl", func(t *testing.T) {
		cache := NewScriptCache(10, time.Nanosecond)
		first, err := cache.GetOrCompile(cachedScript, DefaultSieveExtensions)
		if err != nil {
			t.Fatalf("GetOrCompile: %v", err)
		}
		time.Sleep(time.Millisecond)
		second, err := cache.GetOrCompile(cachedScript, DefaultSieveExtensions)
		if err != nil {
			t.Fatalf("GetOrCompile (after ttl): %v", err)
		}
		if first == second {
			t.Errorf("expired entry must be recompiled")
		}
	})

	t.Run("least recently used entry is evicted", func(t *testing.T) {
		cache := NewScriptCache(2, time.Minute)
		third := "require \"fileinto\";\nfileinto \"Third\";\n"

		one, _ := cache.GetOrCompile(cachedScript, DefaultSieveExtensions)
		if _, err := cache.GetOrCompile(editedScript, DefaultSieveExtensions); err != nil {
			t.Fatalf("GetOrCompile(edited): %v", err)
		}
		// Keep the first warm, so the second is the least recently used when a third arrives.
		if again, _ := cache.GetOrCompile(cachedScript, DefaultSieveExtensions); again != one {
			t.Fatalf("the first entry should still be cached")
		}
		if _, err := cache.GetOrCompile(third, DefaultSieveExtensions); err != nil {
			t.Fatalf("GetOrCompile(third): %v", err)
		}
		if again, _ := cache.GetOrCompile(cachedScript, DefaultSieveExtensions); again != one {
			t.Errorf("recently used entry was evicted instead of the oldest one")
		}
	})
}

func TestScriptCacheCompileErrorNotCached(t *testing.T) {
	cache := NewScriptCache(10, time.Minute)

	if _, err := cache.GetOrCompile(`this is not sieve`, DefaultSieveExtensions); err == nil {
		t.Fatalf("expected a compile error for an invalid script")
	}
	compiled, err := cache.GetOrCompile(cachedScript, DefaultSieveExtensions)
	if err != nil {
		t.Fatalf("GetOrCompile after failure: %v", err)
	}
	if compiled == nil {
		t.Fatalf("expected a compiled script after the failed attempt")
	}
}

// TestScriptCacheSharedEntryIsNotBoundToAnAccount pins what makes one cache safe to share
// between accounts and between delivery paths: the cached value is the parse, which knows
// nothing about who is being delivered to. Two accounts whose scripts are byte-identical
// (a shared template, a copied rule) collide on one entry by design, so each account's
// executor must still evaluate as that account - a cache of ready-made executors could
// not offer that.
func TestScriptCacheSharedEntryIsNotBoundToAnAccount(t *testing.T) {
	const (
		script     = "redirect \"forward@example.com\";\r\n"
		accountA   = int64(100)
		accountB   = int64(200)
		rateLimit  = 10
		rateWindow = time.Hour
	)
	cache := NewScriptCache(10, time.Minute)

	compiledA, err := cache.GetOrCompile(script, DefaultSieveExtensions)
	if err != nil {
		t.Fatalf("account A: %v", err)
	}
	compiledB, err := cache.GetOrCompile(script, DefaultSieveExtensions)
	if err != nil {
		t.Fatalf("account B: %v", err)
	}
	if compiledA != compiledB {
		t.Fatalf("identical scripts must share one compiled copy")
	}

	for _, tc := range []struct {
		name      string
		accountID int64
	}{{"account A", accountA}, {"account B", accountB}} {
		oracle := &recordingRedirectOracle{}
		executor := compiledB.NewExecutor(tc.accountID, nil, oracle, rateLimit, rateWindow, 0)
		if _, err := executor.Evaluate(context.Background(), Context{
			EnvelopeFrom: "sender@example.com",
			EnvelopeTo:   "recipient@example.com",
			Header:       map[string][]string{"From": {"sender@example.com"}},
			Body:         "body",
		}); err != nil {
			t.Fatalf("%s: evaluate: %v", tc.name, err)
		}
		if len(oracle.accountIDs) == 0 {
			t.Fatalf("%s: the redirect oracle was never consulted", tc.name)
		}
		for _, id := range oracle.accountIDs {
			if id != tc.accountID {
				t.Errorf("%s: redirect attributed to account %d, want %d", tc.name, id, tc.accountID)
			}
		}
	}
}

func TestScriptCacheConcurrentUse(t *testing.T) {
	cache := NewScriptCache(4, time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// A handful of distinct scripts, more than the cache holds, so lookups,
			// inserts and evictions all race.
			script := fmt.Sprintf("%s# %d\n", cachedScript, i%8)
			compiled, err := cache.GetOrCompile(script, DefaultSieveExtensions)
			if err != nil {
				t.Errorf("GetOrCompile: %v", err)
				return
			}
			got, err := evaluateFileintoTarget(compiled)
			if err != nil {
				t.Errorf("evaluate: %v", err)
				return
			}
			if got != "Archive" {
				t.Errorf("filed into %q, want Archive", got)
			}
		}(i)
	}
	wg.Wait()
}

// recordingRedirectOracle records which account each redirect check was attributed to.
type recordingRedirectOracle struct {
	accountIDs []int64
}

func (o *recordingRedirectOracle) CountRedirectsSince(ctx context.Context, accountID int64, window time.Duration) (int, error) {
	o.accountIDs = append(o.accountIDs, accountID)
	return 0, nil
}

func (o *recordingRedirectOracle) RecordRedirect(ctx context.Context, accountID int64) error {
	o.accountIDs = append(o.accountIDs, accountID)
	return nil
}

// evaluateFileintoTarget runs a compiled fileinto script and reports the target mailbox.
func evaluateFileintoTarget(compiled *CompiledScript) (string, error) {
	result, err := compiled.NewExecutor(1, nil, nil, 0, 0, 0).Evaluate(context.Background(), Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header:       map[string][]string{"From": {"sender@example.com"}},
		Body:         "body",
	})
	if err != nil {
		return "", err
	}
	return result.Mailbox, nil
}
