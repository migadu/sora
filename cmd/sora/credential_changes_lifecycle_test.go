package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/authcache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
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

type lifecycleTestDBConfig struct {
	Database struct {
		Write struct {
			Hosts    []string `toml:"hosts"`
			Port     int      `toml:"port"`
			User     string   `toml:"user"`
			Password string   `toml:"password"`
			Name     string   `toml:"name"`
			TLS      bool     `toml:"tls"`
		} `toml:"write"`
	} `toml:"database"`
}

func lifecycleResilientDB(t *testing.T, suffix string) *resilient.ResilientDatabase {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	ctx := context.Background()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var configPath string
	for {
		candidate := filepath.Join(dir, "config-test.toml")
		if _, err := os.Stat(candidate); err == nil {
			configPath = candidate
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("config-test.toml not found")
		}
		dir = parent
	}
	var cfg lifecycleTestDBConfig
	if _, err := toml.DecodeFile(configPath, &cfg); err != nil {
		t.Fatalf("decode config-test.toml: %v", err)
	}
	if name := os.Getenv("SORA_TEST_DB_NAME"); name != "" {
		cfg.Database.Write.Name = name
	}
	cfg.Database.Write.Name += suffix
	endpoint := &config.DatabaseEndpointConfig{
		Hosts:    cfg.Database.Write.Hosts,
		Port:     cfg.Database.Write.Port,
		User:     cfg.Database.Write.User,
		Password: cfg.Database.Write.Password,
		Name:     cfg.Database.Write.Name,
		TLSMode:  cfg.Database.Write.TLS,
	}
	if suffix != "" {
		maint := *endpoint
		maint.Name = "postgres"
		admin, err := db.NewDatabaseFromConfig(ctx, &config.DatabaseConfig{Write: &maint}, false)
		if err != nil {
			t.Fatalf("connect postgres maintenance db: %v", err)
		}
		var exists bool
		if err := admin.GetWritePool().QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", endpoint.Name).Scan(&exists); err != nil {
			admin.Close()
			t.Fatalf("check test db existence: %v", err)
		}
		if !exists {
			if _, err := admin.GetWritePool().Exec(ctx, "CREATE DATABASE "+pgx.Identifier{endpoint.Name}.Sanitize()); err != nil {
				admin.Close()
				t.Fatalf("create test db %s: %v", endpoint.Name, err)
			}
		}
		admin.Close()
	}
	rawDB, err := db.NewDatabaseFromConfig(ctx, &config.DatabaseConfig{Write: endpoint}, true)
	if err != nil {
		t.Fatalf("migrate test db %s: %v", endpoint.Name, err)
	}
	if _, err := rawDB.GetWritePool().Exec(ctx, "CREATE EXTENSION IF NOT EXISTS pg_trgm"); err != nil {
		rawDB.Close()
		t.Fatalf("create pg_trgm: %v", err)
	}
	rawDB.Close()

	rdb, err := resilient.NewResilientDatabase(ctx, &config.DatabaseConfig{Write: endpoint}, false, false)
	if err != nil {
		t.Fatalf("open resilient db %s: %v", endpoint.Name, err)
	}
	t.Cleanup(rdb.Close)
	return rdb
}

func createLifecycleAccount(t *testing.T, rdb *resilient.ResilientDatabase, label string) (int64, string) {
	t.Helper()
	ctx := context.Background()
	email := fmt.Sprintf("startup-%s-%d@example.com", label, time.Now().UnixNano())
	id, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email:     email,
		Password:  "first-password",
		IsPrimary: true,
		HashType:  "bcrypt",
	})
	if err != nil {
		t.Fatal(err)
	}
	return id, email
}

func deleteLifecycleAccount(t *testing.T, rdb *resilient.ResilientDatabase, email string) {
	t.Helper()
	if err := rdb.DeleteAccountWithRetry(context.Background(), email); err != nil {
		t.Fatal(err)
	}
}

func waitCacheResumed(cache *lookupcache.LookupCache, serverName, username string, accountID int64, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cache.Set(serverName, username, &lookupcache.CacheEntry{AccountID: accountID})
		if _, found := cache.Get(serverName, username); found {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// startServers calls startCredentialChanges before launching any server goroutines.
// When [auth_cache] is disabled, initial Refresh sees zero sinks and returns without
// advancing cursor; even when [auth_cache] is enabled, each server's registerServer
// suspends its LookupCache after initial Refresh ran. Registering servers must wake
// the watcher promptly instead of leaving LookupCaches suspended (and Retained Removed
// history unsynchronized) for the first 5s PollInterval of live traffic.
func TestStartCredentialChangesSynchronizesRegisteredServersPromptlyWithoutAuthCache(t *testing.T) {
	rdb := lifecycleResilientDB(t, "_sora_startup")
	activeID, activeEmail := createLifecycleAccount(t, rdb, "active")
	_, removedEmail := createLifecycleAccount(t, rdb, "removed-before-boot")
	deleteLifecycleAccount(t, rdb, removedEmail)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		time.Sleep(25 * time.Millisecond)
	})

	firstCache := lifecycleCache(t)
	tracker := server.NewConnectionTracker("IMAP", "imap", "localhost", "localhost-imap", nil, 0, 0, 0, true)
	t.Cleanup(tracker.Stop)

	deps := &serverDependencies{
		resilientDB:        rdb,
		connectionTrackers: make(map[string]*server.ConnectionTracker),
	}

	// Exact startServers sequence: startCredentialChanges runs before expectRegistrations
	// and before any server registers its tracker or LookupCache.
	startCredentialChanges(ctx, deps)
	deps.expectRegistrations([]config.ServerConfig{{Type: "imap", Name: "imap"}})

	deps.connectionTrackersMux.Lock()
	deps.connectionTrackers["IMAP-imap"] = tracker
	deps.connectionTrackersMux.Unlock()
	deps.registerServer("imap", fakeCachingServer{cache: firstCache})

	if !waitCacheResumed(firstCache, "imap", activeEmail, activeID, 500*time.Millisecond) {
		t.Fatal("registered server LookupCache remained suspended after startup registration instead of synchronizing promptly")
	}

	// Unrelated login started after initial startup synchronization must not be kicked by
	// historical Removed rows on subsequent registrations/polls.
	gen := tracker.SessionGeneration()

	secondCache := lifecycleCache(t)
	deps.registerServer("pop3", fakeCachingServer{cache: secondCache})
	if !waitCacheResumed(secondCache, "pop3", activeEmail, activeID, 500*time.Millisecond) {
		t.Fatal("dynamically registered server LookupCache remained suspended instead of waking watcher promptly")
	}
	if _, found := firstCache.Get("imap", activeEmail); !found {
		t.Fatal("waking watcher for a newly registered server evicted warm entries from healthy sibling cache")
	}
	session := tracker.RegisterSessionIfGeneration(activeID, gen)
	select {
	case <-session:
		t.Fatal("historical Removed row was not synchronized at startup and kicked a subsequent live login")
	default:
	}
}

func TestStartCredentialChangesSynchronizesTrackersPromptlyWhenCachesDisabled(t *testing.T) {
	rdb := lifecycleResilientDB(t, "_sora_startup")
	_, removedEmail := createLifecycleAccount(t, rdb, "removed-nocache")
	deleteLifecycleAccount(t, rdb, removedEmail)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		time.Sleep(25 * time.Millisecond)
	})

	tracker := server.NewConnectionTracker("IMAP", "imap-nocache", "localhost", "localhost-imap-nocache", nil, 0, 0, 0, true)
	t.Cleanup(tracker.Stop)

	deps := &serverDependencies{
		resilientDB:        rdb,
		connectionTrackers: make(map[string]*server.ConnectionTracker),
	}

	startCredentialChanges(ctx, deps)
	deps.expectRegistrations([]config.ServerConfig{{Type: "imap", Name: "imap-nocache"}})

	deps.connectionTrackersMux.Lock()
	deps.connectionTrackers["IMAP-imap-nocache"] = tracker
	deps.connectionTrackersMux.Unlock()
	deps.registerServer("imap-nocache", fakeCachingServer{cache: nil})

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && tracker.SessionGeneration() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if tracker.SessionGeneration() == 0 {
		t.Fatal("initial credential_changes synchronization did not run promptly for tracker-only startup when caches are disabled")
	}
}
