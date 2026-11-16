package main

import (
	"context"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/server/credchanges"
)

// credentialChangesInitialReadTimeout bounds the read at startup, which runs before any
// server accepts a connection.
const credentialChangesInitialReadTimeout = 10 * time.Second

// loginCacheHolder is a server that caches logins. Every server that does must implement
// it, or a changed account keeps signing in through it from the cache.
type loginCacheHolder interface {
	GetLookupCache() *lookupcache.LookupCache
}

// startCredentialChanges synchronizes the primary revocation feed before serving
// cached logins. Initialization/read/sink failures keep caches suspended; normal
// primary authentication remains available. Remote-only nodes have no local feed.
func startCredentialChanges(ctx context.Context, deps *serverDependencies) {
	if deps.resilientDB == nil {
		return
	}

	sinks := credchanges.Sinks{
		LoginCaches:  deps.loginCaches,
		Sessions:     deps.sessionEnders,
		Suspend:      deps.suspendCredentialCaches,
		Synchronized: deps.resumeCredentialCaches,
		Reset:        deps.resetCredentialState,
	}
	var lookback time.Duration
	if deps.authCacheInstance != nil {
		sinks.AuthCache = deps.authCacheInstance
		lookback = deps.authCacheInstance.MaxAge()
	}

	// The first successful primary identity read binds persisted cache rows to
	// this logical database and tracking migration. Old/unrelated cache rows are
	// flushed atomically while suspended; failed setup is retried by the watcher.
	namespaceEnsured := false
	load := func(ctx context.Context, cursor int64) (db.CredentialChanges, error) {
		if !namespaceEnsured && deps.authCacheInstance != nil {
			identity, err := deps.resilientDB.GetDatabaseIdentityWithRetry(ctx)
			if err != nil {
				return db.CredentialChanges{}, err
			}
			if err := deps.authCacheInstance.EnsureRevocationNamespace(ctx, identity); err != nil {
				return db.CredentialChanges{}, err
			}
			namespaceEnsured = true
		}
		return deps.resilientDB.GetCredentialChangesSinceWithRetry(ctx, cursor)
	}
	w := credchanges.New(load, deps.resilientDB.PruneCredentialChangesWithRetry, sinks, lookback)
	readCtx, cancel := context.WithTimeout(ctx, credentialChangesInitialReadTimeout)
	err := w.Refresh(readCtx)
	cancel()
	if err != nil {
		logger.Warn("Credential changes: initial synchronization failed; login caches remain suspended and authentication falls back to primary reads", "error", err)
	}
	go w.Run(ctx, credchanges.PollInterval)
}

// lookupCaches returns a snapshot, including caches introduced by reload.
func (deps *serverDependencies) lookupCaches() []*lookupcache.LookupCache {
	deps.runningServersMux.Lock()
	defer deps.runningServersMux.Unlock()
	var caches []*lookupcache.LookupCache
	for _, srv := range deps.runningServers {
		if holder, ok := srv.(loginCacheHolder); ok {
			if c := holder.GetLookupCache(); c != nil {
				caches = append(caches, c)
			}
		}
	}
	return caches
}

func (deps *serverDependencies) loginCaches() []credchanges.LoginCache {
	var result []credchanges.LoginCache
	for _, c := range deps.lookupCaches() {
		result = append(result, c)
	}
	return result
}

func (deps *serverDependencies) suspendCredentialCaches() {
	if deps.authCacheInstance != nil {
		deps.authCacheInstance.Suspend()
	}
	for _, c := range deps.lookupCaches() {
		c.Suspend()
	}
}

func (deps *serverDependencies) resumeCredentialCaches(ctx context.Context) error {
	if deps.authCacheInstance != nil {
		if err := deps.authCacheInstance.Resume(ctx); err != nil {
			return err
		}
	}
	for _, c := range deps.lookupCaches() {
		c.Resume()
	}
	return nil
}

// A retention/clock gap has lost account-level attribution: clear all local
// verdicts and terminate all local sessions before acknowledging a fresh cursor.
func (deps *serverDependencies) resetCredentialState(ctx context.Context) error {
	deps.suspendCredentialCaches()
	var firstErr error
	if deps.authCacheInstance != nil {
		firstErr = deps.authCacheInstance.InvalidateAll(ctx)
	}
	for _, c := range deps.lookupCaches() {
		c.Clear()
	}
	for _, tracker := range deps.connectionTrackersSnapshot() {
		tracker.EndAllLocalSessions()
	}
	return firstErr
}

// sessionEnders returns the connection tracker of every running server that has one.
func (deps *serverDependencies) sessionEnders() []credchanges.SessionEnder {
	deps.connectionTrackersMux.Lock()
	defer deps.connectionTrackersMux.Unlock()
	enders := make([]credchanges.SessionEnder, 0, len(deps.connectionTrackers))
	for _, t := range deps.connectionTrackers {
		if t != nil {
			enders = append(enders, t)
		}
	}
	return enders
}
