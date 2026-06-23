package delivery

import (
	"context"
	"errors"
	"testing"
)

// TestResolveVacationFrom verifies that a user-supplied SIEVE vacation ":from" is
// honored only when it is a syntactically valid address the account owns, and is
// otherwise ignored (falling back to the default) so the auto-reply cannot spoof an
// arbitrary sender/return-path. Regression test for audit finding L3.
func TestResolveVacationFrom(t *testing.T) {
	owned := map[string]bool{"jane@example.com": true, "j.doe@example.com": true}
	h := &StandardVacationHandler{
		IsOwnedAddress: func(_ context.Context, _ int64, addr string) (bool, error) {
			return owned[addr], nil
		},
	}

	cases := []struct {
		name      string
		candidate string
		want      string
	}{
		{"empty falls back", "", ""},
		{"owned address honored", "jane@example.com", "jane@example.com"},
		{"owned alias honored", "j.doe@example.com", "j.doe@example.com"},
		{"unowned address ignored (spoof attempt)", "ceo@victim.com", ""},
		{"malformed ignored", "not-an-address", ""},
		{"display-name form ignored", "Jane <jane@example.com>", ""},
		{"case-insensitive owned match", "Jane@Example.com", "jane@example.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := h.resolveVacationFrom(context.Background(), 1, c.candidate); got != c.want {
				t.Errorf("resolveVacationFrom(%q) = %q, want %q", c.candidate, got, c.want)
			}
		})
	}

	// Fail-closed: no ownership checker wired -> ignore any non-empty :from.
	t.Run("nil checker fails closed", func(t *testing.T) {
		hNil := &StandardVacationHandler{}
		if got := hNil.resolveVacationFrom(context.Background(), 1, "jane@example.com"); got != "" {
			t.Errorf("nil checker should ignore :from, got %q", got)
		}
	})

	// Fail-closed: ownership check error -> ignore :from.
	t.Run("checker error fails closed", func(t *testing.T) {
		hErr := &StandardVacationHandler{
			IsOwnedAddress: func(_ context.Context, _ int64, _ string) (bool, error) {
				return false, errors.New("db unavailable")
			},
		}
		if got := hErr.resolveVacationFrom(context.Background(), 1, "jane@example.com"); got != "" {
			t.Errorf("checker error should ignore :from, got %q", got)
		}
	})
}
