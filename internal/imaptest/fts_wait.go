package imaptest

import (
	"context"
	"fmt"
	"slices"
	"time"
)

const defaultFTSTimeout = 90 * time.Second

// waitForIndexing uses positive complete-word queries as a wire-only readiness
// condition. It permits temporarily missing fixture messages, then lets the
// case run its ordinary assertions unchanged once every fixture is searchable.
func waitForIndexing(s *Session, criterion string, want ...uint64) error {
	return waitForIndexingEvery(s, criterion, 5*time.Second, want...)
}

func waitForIndexingEvery(s *Session, criterion string, interval time.Duration, want ...uint64) error {
	parent := s.ctx
	if parent == nil {
		parent = s.Client.ctx
	}
	if parent == nil {
		parent = context.Background()
	}
	budget := s.cfg.FTSTimeout
	if budget == 0 {
		budget = defaultFTSTimeout
	}
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	expected := slices.Clone(want)
	slices.Sort(expected)
	var last []uint64
	timedOut := func() error {
		if err := contextStateError(parent); err != nil {
			return err
		}
		return &AssertionError{Message: fmt.Sprintf("FTS indexing did not become ready within %s for SEARCH %s: last matches %v, want %v", budget, criterion, last, expected)}
	}
	for {
		if contextStateError(ctx) != nil {
			return timedOut()
		}
		response, err := s.Client.CommandContext(ctx, "SEARCH "+criterion)
		if err != nil {
			if contextStateError(ctx) != nil {
				return timedOut()
			}
			return err
		}
		if response.Status != "OK" {
			return &AssertionError{Message: fmt.Sprintf("FTS readiness SEARCH returned %s: %s", response.Status, response.Text)}
		}
		last, err = response.Search()
		if err != nil {
			return err
		}
		slices.Sort(last)
		for i, seq := range last {
			if !slices.Contains(expected, seq) || i > 0 && last[i-1] == seq {
				return Check(false, "FTS readiness SEARCH %s returned unexpected matches %v, want a subset of %v", criterion, last, expected)
			}
		}
		if slices.Equal(last, expected) {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return timedOut()
		case <-timer.C:
		}
	}
}
