package lookupcache

import (
	"testing"
	"time"
)

func revocationTestCache(t *testing.T) *LookupCache {
	t.Helper()
	c := New("test", t.Name(), time.Hour, time.Minute, 100, time.Hour, time.Hour)
	t.Cleanup(func() { c.Stop(t.Context()) })
	return c
}

func TestRevocationGenerationRejectsLateFillAndPreservesHealthyWarmCache(t *testing.T) {
	c := revocationTestCache(t)
	before := c.Generation()
	c.InvalidateAccounts([]int64{42})
	if c.SetSuccessIfGeneration(before, "user", 42, "hash", "secret") {
		t.Fatal("a verdict read before revocation was cached afterwards")
	}
	c.Set("", "route", &CacheEntry{AccountID: 7})
	c.Resume() // healthy synchronization must not flush warm entries
	if _, found := c.Get("", "route"); !found {
		t.Fatal("healthy Resume flushed a warm entry")
	}
	before = c.Generation()
	c.Suspend()
	if _, found := c.Get("", "route"); found {
		t.Fatal("suspended cache answered a hit")
	}
	if c.SetIfGeneration(before, "", "route", &CacheEntry{AccountID: 42}) {
		t.Fatal("suspended cache accepted old fill")
	}
	if c.SetSuccessIfGeneration(c.Generation(), "user", 42, "hash", "secret") {
		t.Fatal("suspended cache accepted new fill")
	}
	c.Resume()
	if _, found := c.Get("", "route"); found {
		t.Fatal("Resume resurrected pre-suspension entry")
	}
	if !c.SetIfGeneration(c.Generation(), "", "fresh", &CacheEntry{AccountID: 7}) {
		t.Fatal("resumed cache refused current fill")
	}
}

func TestRevocationDuringCachedPasswordVerificationFallsBackToPrimary(t *testing.T) {
	c := revocationTestCache(t)
	c.SetSuccess("user", 42, "hash", "secret")
	old := verifyPassword
	entered, release := make(chan struct{}), make(chan struct{})
	verifyPassword = func(string, string) error { close(entered); <-release; return nil }
	defer func() { verifyPassword = old }()
	done := make(chan bool, 1)
	go func() { _, found, _ := c.Authenticate("user", "secret"); done <- found }()
	<-entered
	c.InvalidateAccounts([]int64{42})
	close(release)
	if <-done {
		t.Fatal("invalidation during bcrypt still returned a cached verdict")
	}
}

func TestRevocationSeparatesSingleflightGenerations(t *testing.T) {
	c := revocationTestCache(t)
	entered, release := make(chan struct{}), make(chan struct{})
	oldDone := make(chan error, 1)
	go func() {
		_, _, err := c.GetOrFetch("proxy", "user", func() (*CacheEntry, error) {
			close(entered)
			<-release
			return &CacheEntry{AccountID: 42, ExpiresAt: time.Now().Add(time.Hour)}, nil
		})
		oldDone <- err
	}()
	<-entered
	c.InvalidateAccount(42)
	freshDone := make(chan int64, 1)
	go func() {
		e, _, err := c.GetOrFetch("proxy", "user", func() (*CacheEntry, error) {
			return &CacheEntry{AccountID: 7, ExpiresAt: time.Now().Add(time.Hour)}, nil
		})
		if err != nil {
			freshDone <- -1
			return
		}
		freshDone <- e.AccountID
	}()
	select {
	case id := <-freshDone:
		if id != 7 {
			t.Errorf("new generation got account %d, want7", id)
		}
	case <-time.After(2 * time.Second):
		t.Error("new generation joined the old blocked lookup")
	}
	close(release)
	if err := <-oldDone; err != nil {
		t.Fatal(err)
	}
	entry, found := c.Get("proxy", "user")
	if !found || entry.AccountID != 7 {
		t.Fatal("old fetch replaced or removed the fresh generation")
	}
}
