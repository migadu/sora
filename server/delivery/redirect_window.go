package delivery

import (
	"context"
	"time"

	"github.com/migadu/sora/logger"
)

// RedirectWindowSource reads the redirect rate windows other servers charge redirects under.
type RedirectWindowSource interface {
	RedirectRateWindowsOtherThanWithRetry(ctx context.Context, windows []time.Duration) ([]time.Duration, error)
}

// WatchRedirectRateWindows warns when the Sieve redirect rate limit is applied with more
// than one limits.redirect_rate_window: windows are this node's (config.RedirectRateWindows),
// and every interval until ctx ends, starting now, it looks for redirects still inside a
// window charged by a server with another one. The limit counts an account's redirects
// within the window of the server that delivers, and the cleaner keeps a redirect until the
// window that charged it has passed, so with two windows an account's limit depends on the
// node that delivers, and the longer window may not see redirects the shorter one charged
// (#1994). A changed window that is rolling out is reported until the old window's
// redirects have aged out.
func WatchRedirectRateWindows(ctx context.Context, source RedirectWindowSource, windows []time.Duration, interval time.Duration) {
	if len(windows) == 0 {
		return
	}
	if len(windows) > 1 {
		logger.Warn("Sieve: the lmtp and http_admin_api servers of this node apply the redirect rate limit with different limits.redirect_rate_window values; "+
			"an account's limit then depends on the server that delivers: use one window on every lmtp and http_admin_api server of every node",
			"windows", windows)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		checkRedirectRateWindows(ctx, source, windows)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// checkRedirectRateWindows logs a warning when redirects still inside their window were
// charged under a redirect_rate_window that is none of windows.
func checkRedirectRateWindows(ctx context.Context, source RedirectWindowSource, windows []time.Duration) {
	other, err := source.RedirectRateWindowsOtherThanWithRetry(ctx, windows)
	if err != nil {
		if ctx.Err() == nil {
			logger.Debug("Sieve: could not compare the redirect rate windows of the cluster", "error", err)
		}
		return
	}
	if len(other) > 0 {
		logger.Warn("Sieve: redirects were charged under a limits.redirect_rate_window other than this node's; "+
			"the window must be the same on every lmtp and http_admin_api server of every node, or an account's redirect limit depends on the node that delivers "+
			"(expected while a changed window rolls out, until the old window's redirects have aged out)",
			"windows", windows, "other_windows", other)
	}
}
