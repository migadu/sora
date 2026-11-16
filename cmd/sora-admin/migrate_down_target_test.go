package main

import (
	"strings"
	"testing"
)

// TestDownTarget (#1667): migrate down walks the embedded migrations, which have gaps,
// never goes past the first one, and refuses a database version it has no migration for.
func TestDownTarget(t *testing.T) {
	versions := []uint{1, 2, 4, 5} // no 3, like the gaps at 000032 and 000063
	for _, tc := range []struct {
		name    string
		current uint
		limit   int
		all     bool
		want    uint
		wantErr string
	}{
		{name: "one", current: 5, limit: 1, want: 4},
		{name: "across a gap", current: 4, limit: 1, want: 2},
		{name: "down to the first", current: 5, limit: 3, want: 1},
		{name: "past the first", current: 5, limit: 4, wantErr: "would revert the first migration (1)"},
		{name: "at the first", current: 1, limit: 1, wantErr: "would revert the first migration (1)"},
		{name: "all", current: 5, limit: 1, all: true, want: 1},
		{name: "all at the first", current: 1, limit: 1, all: true, want: 1},
		{name: "version in a gap", current: 3, limit: 1, wantErr: "not one of this binary's migrations"},
		{name: "version newer than the binary", current: 6, all: true, wantErr: "not one of this binary's migrations"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := downTarget(versions, tc.current, tc.limit, tc.all)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("downTarget = %d, %v; want an error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("downTarget = %d, %v; want %d", got, err, tc.want)
			}
		})
	}
}
