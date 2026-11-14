package main

import (
	"context"
	"time"

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

// startCredentialChanges makes changed credentials hold on this node: every
// credchanges.PollInterval it reads credential_changes and drops the changed accounts from
// the persistent auth cache and from the lookup cache of every running server, and ends
// this node's sessions of accounts taken out of service. It does nothing on a node without
// a database (a proxy that only uses remote lookup), whose cached logins answer to the
// lookup service and expire with the cache's positive_ttl.
//
// The first read happens before it returns, and before any server starts: the persistent
// auth cache survives a restart, so it may hold a login that changed while the node was
// down. That read goes back the cache's max_age (capped to credchanges.Retention where the
// cache is opened). If it fails, the next one starts from the same point.
func startCredentialChanges(ctx context.Context, deps *serverDependencies) {
	if deps.resilientDB == nil {
		return
	}

	sinks := credchanges.Sinks{
		LoginCaches: deps.loginCaches,
		Sessions:    deps.sessionEnders,
	}
	var lookback time.Duration
	if deps.authCacheInstance != nil {
		sinks.AuthCache = deps.authCacheInstance
		lookback = deps.authCacheInstance.MaxAge()
	}

	w := credchanges.New(deps.resilientDB.GetCredentialChangesSinceWithRetry, deps.resilientDB.PruneCredentialChangesWithRetry, sinks, lookback)
	readCtx, cancel := context.WithTimeout(ctx, credentialChangesInitialReadTimeout)
	err := w.Refresh(readCtx)
	cancel()
	if err != nil {
		logger.Warn("Credential changes: initial read failed - the persistent auth cache may hold logins changed while this node was down, until a read succeeds", "error", err)
	}
	go w.Run(ctx, credchanges.PollInterval)
}

// loginCaches returns the lookup cache of every running server that has one.
func (deps *serverDependencies) loginCaches() []credchanges.LoginCache {
	deps.runningServersMux.Lock()
	defer deps.runningServersMux.Unlock()
	var caches []credchanges.LoginCache
	for _, s := range deps.runningServers {
		if holder, ok := s.(loginCacheHolder); ok {
			if c := holder.GetLookupCache(); c != nil {
				caches = append(caches, c)
			}
		}
	}
	return caches
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
