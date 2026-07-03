package imap

import (
	"context"
	"time"
)

// CommandTimeouts holds per-command hard timeout limits. A zero value means no
// command-specific timeout is applied (the parent context — connection-level or
// session-level — still governs cancellation). These protect the server from
// "query of death" scenarios where a single expensive command could tie up
// resources indefinitely.
//
// The defaults are deliberately generous: they are safety nets, not
// performance targets. Operators can tighten them via configuration.
type CommandTimeouts struct {
	Search      time.Duration // SEARCH, default 30s
	Sort        time.Duration // SORT, default 30s
	Thread      time.Duration // THREAD, default 30s
	MultiSearch time.Duration // MULTISEARCH, default 30s
	Fetch       time.Duration // FETCH, default 30s (large body downloads)
	Store       time.Duration // STORE, default 15s
	Copy        time.Duration // COPY, default 30s (may involve S3 copies)
	Move        time.Duration // MOVE, default 30s (may involve S3 copies)
}

// DefaultCommandTimeouts returns the default timeout set. These are high-water
// safety limits — well above normal operation — that prevent runaway commands
// from monopolising server resources.
func DefaultCommandTimeouts() CommandTimeouts {
	return CommandTimeouts{
		Search:      30 * time.Second,
		Sort:        30 * time.Second,
		Thread:      30 * time.Second,
		MultiSearch: 30 * time.Second,
		Fetch:       30 * time.Second,
		Store:       15 * time.Second,
		Copy:        30 * time.Second,
		Move:        30 * time.Second,
	}
}

// defaultCommandTimeouts returns a pointer to the default timeouts, for use in
// the server constructor.
func defaultCommandTimeouts() *CommandTimeouts {
	t := DefaultCommandTimeouts()
	return &t
}

// ApplyOverrides merges operator-supplied overrides (from the TOML config) into
// the receiver. Only non-zero entries in the map are applied; everything else
// keeps its current (default) value.
func (ct *CommandTimeouts) ApplyOverrides(overrides map[string]time.Duration) {
	for name, d := range overrides {
		switch name {
		case "search":
			ct.Search = d
		case "sort":
			ct.Sort = d
		case "thread":
			ct.Thread = d
		case "multi_search":
			ct.MultiSearch = d
		case "fetch":
			ct.Fetch = d
		case "store":
			ct.Store = d
		case "copy":
			ct.Copy = d
		case "move":
			ct.Move = d
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
	case "SEARCH":
		timeout = timeouts.Search
	case "SORT":
		timeout = timeouts.Sort
	case "THREAD":
		timeout = timeouts.Thread
	case "MULTISEARCH":
		timeout = timeouts.MultiSearch
	case "FETCH":
		timeout = timeouts.Fetch
	case "STORE":
		timeout = timeouts.Store
	case "COPY":
		timeout = timeouts.Copy
	case "MOVE":
		timeout = timeouts.Move
	}

	if timeout <= 0 {
		return ctx, func() {}
	}

	return context.WithTimeout(ctx, timeout)
}
