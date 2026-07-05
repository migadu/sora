package pop3

import (
	"context"
	"time"
)

// CommandTimeouts holds per-command hard timeout limits, mirroring the IMAP
// and ManageSieve CommandTimeouts. A zero value means no command-specific
// timeout is applied (the library's per-command context — cancelled on
// connection teardown or server shutdown — still governs cancellation). These
// protect the server from a wedged backend (slow database, stuck lock) tying
// up a session goroutine indefinitely.
//
// The timeouts cover only server-side work: RETR/TOP materialise the message
// body (cache/S3/DB) inside the session method and hand the library an
// in-memory reader, so streaming to a slow client is never on the clock.
// USER/PASS/APOP/AUTH are deliberately not covered: they are paced by the
// progressive auth delay (up to auth_rate_limit max_delay, default 30s),
// which a hard cap would fight.
type CommandTimeouts struct {
	Stat time.Duration // STAT, default 10s (first-touch maildrop load)
	List time.Duration // LIST, default 10s
	Uidl time.Duration // UIDL, default 10s
	Retr time.Duration // RETR, default 30s (body fetch from cache/S3)
	Top  time.Duration // TOP, default 30s (body fetch from cache/S3)
	Dele time.Duration // DELE, default 10s
	Quit time.Duration // QUIT, default 15s (UPDATE-phase batch expunge write)
}

// DefaultCommandTimeouts returns the default timeout set. The maildrop
// operations are bounded queries (the listing is capped by the POP3 load
// limit) — milliseconds when healthy — so 10s is a generous safety net.
// RETR/TOP may fetch the body from S3 on a cache miss and get 30s (matching
// IMAP FETCH); QUIT's batch expunge is a single write and gets 15s (matching
// IMAP STORE).
func DefaultCommandTimeouts() CommandTimeouts {
	return CommandTimeouts{
		Stat: 10 * time.Second,
		List: 10 * time.Second,
		Uidl: 10 * time.Second,
		Retr: 30 * time.Second,
		Top:  30 * time.Second,
		Dele: 10 * time.Second,
		Quit: 15 * time.Second,
	}
}

// defaultCommandTimeouts returns a pointer to the default timeouts, for use in
// the server constructor.
func defaultCommandTimeouts() *CommandTimeouts {
	t := DefaultCommandTimeouts()
	return &t
}

// ApplyOverrides merges operator-supplied overrides (from the TOML config) into
// the receiver. Only entries present in the map are applied; everything else
// keeps its current (default) value. An explicit zero disables the timeout for
// that command.
func (ct *CommandTimeouts) ApplyOverrides(overrides map[string]time.Duration) {
	for name, d := range overrides {
		switch name {
		case "stat":
			ct.Stat = d
		case "list":
			ct.List = d
		case "uidl":
			ct.Uidl = d
		case "retr":
			ct.Retr = d
		case "top":
			ct.Top = d
		case "dele":
			ct.Dele = d
		case "quit":
			ct.Quit = d
		}
	}
}

// applyCommandTimeout wraps ctx with a command-specific deadline if one is
// configured for the given command name. If timeouts is nil or the command has
// no timeout (zero value), the original context is returned unchanged.
//
// The caller MUST call the returned cancel function (it is a no-op when no
// timeout is applied).
func applyCommandTimeout(ctx context.Context, command string, timeouts *CommandTimeouts) (context.Context, context.CancelFunc) {
	if timeouts == nil {
		return ctx, func() {}
	}

	var timeout time.Duration
	switch command {
	case "STAT":
		timeout = timeouts.Stat
	case "LIST":
		timeout = timeouts.List
	case "UIDL":
		timeout = timeouts.Uidl
	case "RETR":
		timeout = timeouts.Retr
	case "TOP":
		timeout = timeouts.Top
	case "DELE":
		timeout = timeouts.Dele
	case "QUIT":
		timeout = timeouts.Quit
	}

	if timeout <= 0 {
		return ctx, func() {}
	}

	return context.WithTimeout(ctx, timeout)
}
