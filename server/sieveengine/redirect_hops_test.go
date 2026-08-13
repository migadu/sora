package sieveengine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/helpers"
)

// TestRedirectHopBackstopIsEnforced covers the mail-loop backstop configured by
// [servers.*.limits] max_redirect_hops: a message Sora has already redirected
// that many times must not be redirected again.
//
// Evaluate builds a fresh per-execution SievePolicy from the executor's template
// policy, so every field the backstop reads has to be carried across; a field
// left out silently reads as its zero value, and maxRedirectHops <= 0 means
// "backstop disabled".
func TestRedirectHopBackstopIsEnforced(t *testing.T) {
	const maxHops = 2

	ctxWithHops := func(hops int) Context {
		c := cleanRedirectCtx()
		if hops > 0 {
			c.Header[helpers.RedirectLoopHeader] = []string{fmt.Sprintf("%d", hops)}
		}
		return c
	}

	evalWithHopCap := func(t *testing.T, deliveryCtx Context) Result {
		t.Helper()
		oracle := &configurableRedirectOracle{}
		exts := []string{"envelope", "fileinto", "redirect", "encoded-character", "imap4flags", "variables", "relational", "vacation", "copy", "regex"}
		executor, err := NewSieveExecutorWithOracleAndExtensions(
			`redirect "forward@example.net";`, 1, nil, oracle, 0, time.Hour, maxHops, exts)
		if err != nil {
			t.Fatalf("failed to create executor: %v", err)
		}
		res, err := executor.Evaluate(context.Background(), deliveryCtx)
		if err != nil {
			t.Fatalf("failed to evaluate: %v", err)
		}
		return res
	}

	t.Run("under the cap the redirect proceeds", func(t *testing.T) {
		if got := evalWithHopCap(t, ctxWithHops(maxHops-1)).Action; got != ActionRedirect {
			t.Errorf("action with %d prior hops = %v, want %v", maxHops-1, got, ActionRedirect)
		}
	})

	t.Run("at the cap the redirect is refused", func(t *testing.T) {
		if got := evalWithHopCap(t, ctxWithHops(maxHops)).Action; got != ActionKeep {
			t.Errorf("action with %d prior hops = %v, want %v: max_redirect_hops=%d must stop the loop",
				maxHops, got, ActionKeep, maxHops)
		}
	})

	t.Run("past the cap the redirect is refused", func(t *testing.T) {
		if got := evalWithHopCap(t, ctxWithHops(maxHops+5)).Action; got != ActionKeep {
			t.Errorf("action with %d prior hops = %v, want %v", maxHops+5, got, ActionKeep)
		}
	})
}
