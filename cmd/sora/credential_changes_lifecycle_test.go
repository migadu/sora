package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/migadu/sora/authcache"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

func lifecycleCache(t *testing.T) *lookupcache.LookupCache {
	t.Helper()
	c := lookupcache.New("test", t.Name(), time.Hour, time.Minute, 10, time.Hour, time.Hour)
	t.Cleanup(func() { c.Stop(t.Context()) })
	return c
}

func TestCredentialChangesSuspendNewAndReloadedCachesBeforeServing(t *testing.T) {
	first := lifecycleCache(t)
	first.Set("", "user", &lookupcache.CacheEntry{AccountID: 42})
	deps := &serverDependencies{resilientDB: &resilient.ResilientDatabase{}}
	deps.registerServer("first", fakeCachingServer{cache: first})
	if _, found := first.Get("", "user"); found {
		t.Fatal("new DB-backed cache served before synchronization")
	}
	if err := deps.resumeCredentialCaches(context.Background()); err != nil {
		t.Fatal(err)
	}
	first.Set("", "user", &lookupcache.CacheEntry{AccountID: 42})
	if err := deps.resumeCredentialCaches(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, found := first.Get("", "user"); !found {
		t.Fatal("healthy synchronization flushed warm cache")
	}
	second := lifecycleCache(t)
	second.Set("", "user", &lookupcache.CacheEntry{AccountID: 7})
	deps.registerServer("second", fakeCachingServer{cache: second})
	if _, found := second.Get("", "user"); found {
		t.Fatal("reloaded cache bypassed synchronization")
	}
	if _, found := first.Get("", "user"); !found {
		t.Fatal("adding a server flushed a healthy sibling")
	}
	deps.suspendCredentialCaches()
	if _, found := first.Get("", "user"); found {
		t.Fatal("failed synchronization left cached logins enabled")
	}
	if err := deps.resumeCredentialCaches(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, found := first.Get("", "user"); found {
		t.Fatal("recovery restored old cached verdicts")
	}
}

func TestCredentialChangesGapResetsOtherSinksDespitePersistentFailure(t *testing.T) {
	persistent, err := authcache.New(filepath.Join(t.TempDir(), "auth.db"), time.Hour, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	persistent.Close() // real SQLite failure; other reset sinks must still run
	cache := lifecycleCache(t)
	cache.Set("", "user", &lookupcache.CacheEntry{AccountID: 42})
	tracker := server.NewConnectionTracker("IMAP", t.Name(), "host", "instance", nil, 0, 0, 0, true)
	t.Cleanup(tracker.Stop)
	session := tracker.RegisterSession(42)
	deps := &serverDependencies{
		authCacheInstance:  persistent,
		runningServers:     map[string]ConfigReloader{"cache": fakeCachingServer{cache: cache}},
		connectionTrackers: map[string]*server.ConnectionTracker{"tracker": tracker},
	}
	if err := deps.resetCredentialState(context.Background()); err == nil {
		t.Fatal("closed SQLite reset unexpectedly succeeded")
	}
	if _, found := cache.Get("", "user"); found {
		t.Fatal("failed persistent reset left L1 enabled")
	}
	select {
	case <-session:
	default:
		t.Fatal("failed persistent reset left local session open")
	}
}
