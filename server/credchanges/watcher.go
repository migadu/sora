// Package credchanges applies the primary's transactionally recorded credential
// changes to local login caches and sessions. Cache hits remain suspended at
// startup and after any synchronization failure until a complete application
// succeeds. Polling cannot deliver a change while its database is unreachable.
package credchanges

import (
	"context"
	"errors"
	"fmt"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"sync"
	"time"
)

const (
	PollInterval = 5 * time.Second
	// Retention bounds both retained observations and persistent-cache max_age.
	Retention     = 7 * 24 * time.Hour
	pruneInterval = time.Hour
)

type LoginCache interface{ InvalidateAccounts(accountIDs []int64) }
type PersistentLoginCache interface {
	InvalidateAccounts(context.Context, []int64) error
}
type SessionEnder interface{ EndLocalSessions(accountID int64) int }

// Sinks must provide the three lifecycle hooks whenever there are active sinks.
// Suspend disables ALL local cache hits and stale fills. Synchronized resumes
// them only after all invalidations/session actions succeeded. Reset flushes all
// local login caches and ends all local sessions after a retention/clock/cursor
// discontinuity; it may not leave old state trusted if any part fails.
type Sinks struct {
	AuthCache    PersistentLoginCache
	LoginCaches  func() []LoginCache
	Sessions     func() []SessionEnder
	Suspend      func()
	Synchronized func(context.Context) error
	Reset        func(context.Context) error
}

type Watcher struct {
	load      func(context.Context, int64) (db.CredentialChanges, error)
	prune     func(context.Context, time.Time) (int64, error)
	sinks     Sinks
	mu        sync.Mutex
	cursor    int64
	appliedAt time.Time
	lastPrune time.Time
	failing   bool
}

// New starts suspended at cursor zero, replaying every retained visible change.
// lookback is retained for caller compatibility; it is not a clock overlap and
// does not filter the feed. Persistent cache max_age must be at most Retention.
func New(load func(context.Context, int64) (db.CredentialChanges, error), prune func(context.Context, time.Time) (int64, error), sinks Sinks, _ time.Duration) *Watcher {
	w := &Watcher{load: load, prune: prune, sinks: sinks}
	if sinks.Suspend != nil {
		sinks.Suspend()
	}
	return w
}

// Refresh acknowledges a snapshot boundary only after every sink and lifecycle
// operation succeeds. Any delivery failure suspends cache use and preserves the entire
// checkpoint. Already-applied invalidations are safe to repeat on retry.
func (w *Watcher) Refresh(ctx context.Context) (retErr error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	defer func() {
		if retErr != nil && w.sinks.Suspend != nil {
			w.sinks.Suspend()
		}
	}()
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
	if w.sinks.Suspend == nil || w.sinks.Synchronized == nil || w.sinks.Reset == nil {
		return errors.New("credential change sinks require Suspend, Synchronized and Reset hooks")
	}
	changes, err := w.load(ctx, w.cursor)
	if err != nil {
		return err
	}
	if changes.ReadAt.IsZero() || changes.NextCursor < 0 {
		return fmt.Errorf("invalid credential change boundary")
	}
	reset := changes.NextCursor < w.cursor || (!w.appliedAt.IsZero() && (changes.ReadAt.Before(w.appliedAt) || changes.ReadAt.Sub(w.appliedAt) >= Retention))
	var errs []error
	if reset {
		w.sinks.Suspend()
		if err := w.sinks.Reset(ctx); err != nil {
			errs = append(errs, fmt.Errorf("reset credential change sinks: %w", err))
		}
	}
	if len(changes.Accounts) > 0 {
		logger.Debug("Credential changes: dropping cached logins", "accounts", len(changes.Accounts), "removed", len(changes.Removed))
		if w.sinks.AuthCache != nil {
			if err := w.sinks.AuthCache.InvalidateAccounts(ctx, changes.Accounts); err != nil {
				errs = append(errs, fmt.Errorf("invalidate persistent login cache: %w", err))
			}
		}
		for _, c := range caches {
			c.InvalidateAccounts(changes.Accounts)
		}
	}
	for _, s := range sessions {
		for _, id := range changes.Removed {
			s.EndLocalSessions(id)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	pruneDue := w.lastPrune.IsZero() || reset || changes.ReadAt.Sub(w.lastPrune) >= pruneInterval
	pruned := false
	if pruneDue {
		if _, err := w.prune(ctx, changes.ReadAt.Add(-Retention)); err != nil {
			// Cleanup failure retains rows longer. It is not a failed delivery and
			// must not disable healthy caches; leave lastPrune for the next retry.
			logger.Warn("Credential changes: cleanup failed; retaining events and retrying", "error", err)
		} else {
			pruned = true
		}
	}
	if err := w.sinks.Synchronized(ctx); err != nil {
		return fmt.Errorf("resume credential change sinks: %w", err)
	}
	// A full Reset covers all local state, including changes pruned during a long
	// outage or below an old cursor after primary/time discontinuity.
	w.cursor = changes.NextCursor
	w.appliedAt = changes.ReadAt
	if pruned {
		w.lastPrune = changes.ReadAt
	}
	return nil
}

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
				logger.Warn("Credential changes: synchronization failed; login caches remain suspended", "error", err)
			}
			w.failing = true
			continue
		}
		if w.failing {
			logger.Info("Credential changes: synchronized; login caches resumed")
		}
		w.failing = false
	}
}
