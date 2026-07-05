package lmtp

import (
	"context"
	"errors"
	"time"
)

// CommandTimeouts holds per-command hard timeout limits, mirroring the IMAP,
// POP3, and ManageSieve CommandTimeouts. A zero value means no
// command-specific timeout is applied (the session context — derived from the
// go-smtp connection context and cancelled on client disconnect or server
// shutdown — still governs cancellation). These protect the server from a
// wedged backend (slow database, stuck lock) holding a delivery goroutine and
// the upstream MTA's delivery slot indefinitely.
//
// Only the two phases that do real server-side work are covered. A timeout
// surfaces as a 4xx temporary failure, so the upstream MTA queues the message
// and retries — mail is never lost. LHLO/MAIL/NOOP/RSET/QUIT are trivial and
// uncapped.
type CommandTimeouts struct {
	Rcpt time.Duration // RCPT, default 10s (account lookup, default-mailbox creation)
	Data time.Duration // DATA processing, default 60s (SIEVE + spool + DB insert; excludes wire reception)
}

// DefaultCommandTimeouts returns the default timeout set. RCPT is a few
// bounded queries. DATA is deliberately generous: the pipeline spans SIEVE
// evaluation (with its own DB reads), local spool write, and the message
// insert — and a cap that fires after the DB commit but before the 250 reply
// turns an upstream retry into a duplicate delivery (absorbed by dedup, but
// better kept rare).
func DefaultCommandTimeouts() CommandTimeouts {
	return CommandTimeouts{
		Rcpt: 10 * time.Second,
		Data: 60 * time.Second,
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
		case "rcpt":
			ct.Rcpt = d
		case "data":
			ct.Data = d
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
	case "RCPT":
		timeout = timeouts.Rcpt
	case "DATA":
		timeout = timeouts.Data
	}

	if timeout <= 0 {
		return ctx, func() {}
	}

	return context.WithTimeout(ctx, timeout)
}

// commandTimedOut reports whether the command's execution cap (applied by
// applyCommandTimeout) expired, as opposed to the context being cancelled by
// client disconnect or server shutdown. Callers use it to classify a context
// error from a capped operation: a fired cap means the server is healthy but
// slow (reply 451, MTA requeues), not shutting down (421).
func commandTimedOut(ctx context.Context) bool {
	return errors.Is(ctx.Err(), context.DeadlineExceeded)
}
