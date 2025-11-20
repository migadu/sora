//go:build integration

package imap_test

import (
	"sync"
	"testing"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_LookupCacheConcurrentAuth reproduces a data race in LookupCache
// where concurrent authentication attempts write to c.hits and c.misses
// fields without proper synchronization.
//
// The race occurs in LookupCache.Authenticate():
// - Line 136: Write to c.misses (during cache miss)
// - Line 144: Write to c.misses (during expired entry)
// - Line 149: Write to c.hits (during cache hit)
//
// All three write to shared fields while only holding RLock, causing
// concurrent writes from multiple goroutines.
//
// This test should FAIL with -race flag before the fix,
// and PASS after adding proper synchronization.
func TestIMAP_LookupCacheConcurrentAuth(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Perform concurrent authentication attempts to trigger the race
	const numConcurrent = 20
	var wg sync.WaitGroup

	// First, do one successful login to populate the cache
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	if err := c1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Initial login failed: %v", err)
	}
	c1.Close()

	// Now perform many concurrent logins
	// These will all hit the cache simultaneously, causing concurrent writes
	// to c.hits (and possibly c.misses if some miss the cache)
	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			c, err := imapclient.DialInsecure(server.Address, nil)
			if err != nil {
				t.Logf("Client %d: Failed to dial: %v", idx, err)
				return
			}
			defer c.Close()

			if err := c.Login(account.Email, account.Password).Wait(); err != nil {
				t.Logf("Client %d: Login failed: %v", idx, err)
				return
			}
		}(i)
	}

	wg.Wait()

	t.Log("✓ Test completed - run with -race to detect lookup cache race before fix")
}
