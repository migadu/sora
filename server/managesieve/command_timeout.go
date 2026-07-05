package managesieve

import (
	"context"
	"time"
)

// CommandTimeouts holds per-command hard timeout limits, mirroring the IMAP
// CommandTimeouts. A zero value means no command-specific timeout is applied
// (the library's per-command context — cancelled on connection teardown or
// server shutdown — still governs cancellation). These protect the server
// from a wedged backend (slow database, stuck lock) tying up a session
// goroutine indefinitely.
//
// The defaults are deliberately generous: they are safety nets, not
// performance targets. Operators can tighten them via configuration.
// AUTHENTICATE/LOGIN are deliberately not covered: they are paced by the
// progressive auth delay (up to auth_rate_limit max_delay, default 30s),
// which a hard cap would fight.
type CommandTimeouts struct {
	ListScripts  time.Duration // LISTSCRIPTS, default 10s
	GetScript    time.Duration // GETSCRIPT, default 10s
	PutScript    time.Duration // PUTSCRIPT, default 10s (go-sieve validation + DB write)
	CheckScript  time.Duration // CHECKSCRIPT, default 10s (go-sieve validation)
	SetActive    time.Duration // SETACTIVE, default 10s (re-validation + DB write)
	DeleteScript time.Duration // DELETESCRIPT, default 10s
	RenameScript time.Duration // RENAMESCRIPT, default 10s
	HaveSpace    time.Duration // HAVESPACE, default 10s
}

// DefaultCommandTimeouts returns the default timeout set. Unlike IMAP's 30s
// defaults (which cover expensive multi-row queries and S3 copies), every
// ManageSieve operation is a single-row query plus validation of a script
// capped at max_script_size — milliseconds when healthy — so 10s is still
// ~1000x normal latency while releasing a wedged session well before
// interactive clients give up.
func DefaultCommandTimeouts() CommandTimeouts {
	return CommandTimeouts{
		ListScripts:  10 * time.Second,
		GetScript:    10 * time.Second,
		PutScript:    10 * time.Second,
		CheckScript:  10 * time.Second,
		SetActive:    10 * time.Second,
		DeleteScript: 10 * time.Second,
		RenameScript: 10 * time.Second,
		HaveSpace:    10 * time.Second,
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
		case "listscripts":
			ct.ListScripts = d
		case "getscript":
			ct.GetScript = d
		case "putscript":
			ct.PutScript = d
		case "checkscript":
			ct.CheckScript = d
		case "setactive":
			ct.SetActive = d
		case "deletescript":
			ct.DeleteScript = d
		case "renamescript":
			ct.RenameScript = d
		case "havespace":
			ct.HaveSpace = d
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
	case "LISTSCRIPTS":
		timeout = timeouts.ListScripts
	case "GETSCRIPT":
		timeout = timeouts.GetScript
	case "PUTSCRIPT":
		timeout = timeouts.PutScript
	case "CHECKSCRIPT":
		timeout = timeouts.CheckScript
	case "SETACTIVE":
		timeout = timeouts.SetActive
	case "DELETESCRIPT":
		timeout = timeouts.DeleteScript
	case "RENAMESCRIPT":
		timeout = timeouts.RenameScript
	case "HAVESPACE":
		timeout = timeouts.HaveSpace
	}

	if timeout <= 0 {
		return ctx, func() {}
	}

	return context.WithTimeout(ctx, timeout)
}
