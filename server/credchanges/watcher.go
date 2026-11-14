// Package credchanges makes a change of credentials hold on every node within seconds,
// whichever node or tool made it and whether or not the nodes form a cluster.
//
// The database records every way a login stops working in credential_changes (by
// trigger: a new password, a removed credential, an account deleted or marked for
// purging). Each node with database access reads that table every PollInterval and drops
// the changed accounts from every login cache it holds: the proxies' persistent auth
// cache, then the in-memory lookup caches. It also ends its own sessions of accounts taken
// out of service. Cluster gossip (the connection trackers' kick and forget-logins events)
// still delivers the Admin API's changes at once where it runs; this is what makes them
// hold where it does not, and what makes changes made around the Admin API hold at all.
//
// The cost is one indexed read per node every PollInterval, independent of the login
// rate: a login served from a cache still costs no database round trip.
package credchanges

import (
	"context"
	"sync"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
)

const (
	// PollInterval is how often a node reads credential_changes: the longest a change
	// made where gossip does not reach can keep working on that node.
	PollInterval = 5 * time.Second

	// Retention is how long credential_changes keeps a row. A restarted node reads back
	// as far as its persistent auth cache reaches, so that cache's max_age is capped to
	// it.
	Retention = 7 * 24 * time.Hour

	// rereadWindow is how far before the previous read each read starts. A row is
	// stamped while its transaction is still open, so a read can pass its time before it
	// commits; going back a window catches it at the next read. It also means a change is
	// applied again at every read for a window's length, which drops a login that a
	// login racing the first application, or reading a lagging replica, cached again.
	rereadWindow = time.Minute

	// pruneInterval is how often a node prunes rows past the retention.
	pruneInterval = time.Hour
)

// LoginCache is an in-memory cache of logins: pkg/lookupcache.LookupCache.
type LoginCache interface {
	InvalidateAccounts(accountIDs []int64)
}

// PersistentLoginCache is the proxies' persistent auth cache: authcache.Cache.
type PersistentLoginCache interface {
	InvalidateAccounts(ctx context.Context, accountIDs []int64) error
}

// SessionEnder ends this node's sessions of an account: server.ConnectionTracker.
type SessionEnder interface {
	EndLocalSessions(accountID int64) int
}

// Sinks is what a node applies credential changes to. LoginCaches and Sessions are asked
// at every read, since servers start (and reload) after the watcher.
type Sinks struct {
	AuthCache   PersistentLoginCache // nil when the node has none
	LoginCaches func() []LoginCache
	Sessions    func() []SessionEnder
}

// Watcher reads credential_changes and applies it to the node's Sinks.
type Watcher struct {
	load  func(ctx context.Context, since time.Time) (db.CredentialChanges, error)
	prune func(ctx context.Context, before time.Time) (int64, error)
	sinks Sinks

	mu        sync.Mutex
	since     time.Time // where the next read starts
	lastPrune time.Time // database clock of the last prune
	failing   bool
}

// New returns a watcher whose first read goes back lookback (at least the reread
// window): the max_age of the node's persistent auth cache, whose entries survive a
// restart, or nothing more when it has none.
func New(load func(ctx context.Context, since time.Time) (db.CredentialChanges, error),
	prune func(ctx context.Context, before time.Time) (int64, error), sinks Sinks, lookback time.Duration) *Watcher {
	return &Watcher{
		load:  load,
		prune: prune,
		sinks: sinks,
		since: time.Now().Add(-max(lookback, rereadWindow)),
	}
}

// Refresh reads the changes since the previous read (less the reread window) and applies
// them. A failed read changes nothing, and the next read starts where this one would
// have, so no change is lost however long the database is away.
func (w *Watcher) Refresh(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var caches []LoginCache
	if w.sinks.LoginCaches != nil {
		caches = w.sinks.LoginCaches()
	}
	var sessions []SessionEnder
	if w.sinks.Sessions != nil {
		sessions = w.sinks.Sessions()
	}
	if w.sinks.AuthCache == nil && len(caches) == 0 && len(sessions) == 0 {
		return nil
	}

	changes, err := w.load(ctx, w.since)
	if err != nil {
		return err
	}
	w.since = changes.ReadAt.Add(-rereadWindow)

	if len(changes.Accounts) > 0 {
		logger.Debug("Credential changes: dropping cached logins", "accounts", len(changes.Accounts), "removed", len(changes.Removed))
		// The persistent cache first: a login that misses an in-memory cache is answered
		// from it, and would fill the in-memory cache again with what it held.
		if w.sinks.AuthCache != nil {
			if err := w.sinks.AuthCache.InvalidateAccounts(ctx, changes.Accounts); err != nil {
				logger.Warn("Credential changes: failed to drop changed accounts from the auth cache", "accounts", len(changes.Accounts), "error", err)
			}
		}
		for _, c := range caches {
			c.InvalidateAccounts(changes.Accounts)
		}
		for _, s := range sessions {
			for _, id := range changes.Removed {
				s.EndLocalSessions(id)
			}
		}
	}

	if w.lastPrune.IsZero() || changes.ReadAt.Sub(w.lastPrune) >= pruneInterval {
		w.lastPrune = changes.ReadAt
		if n, err := w.prune(ctx, changes.ReadAt.Add(-Retention)); err != nil {
			logger.Warn("Credential changes: failed to prune old rows", "error", err)
		} else if n > 0 {
			logger.Debug("Credential changes: pruned old rows", "count", n)
		}
	}
	return nil
}

// Run calls Refresh every interval until ctx is done.
func (w *Watcher) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		refreshCtx, cancel := context.WithTimeout(ctx, max(interval, 5*time.Second))
		err := w.Refresh(refreshCtx)
		cancel()
		if err != nil {
			if !w.failing && ctx.Err() == nil {
				logger.Warn("Credential changes: cannot read credential_changes - cached logins of changed accounts keep working until a read succeeds", "error", err)
			}
			w.failing = true
			continue
		}
		if w.failing {
			logger.Info("Credential changes: reading credential_changes again")
		}
		w.failing = false
	}
}
