package config

import (
	"strings"
	"testing"
)

// A negative [cleanup] fts_retention parses, but delivery then stages a search row only for
// mail sent after a cutoff in the future (none) and the cleaner never prunes, all without a
// word (#284). It is refused at start-up. A value that does not parse keeps falling back to
// the absent-key default (keep every vector), like every other duration key.
func TestCleanupConfigValidate(t *testing.T) {
	for _, tc := range []struct {
		value   string
		wantErr bool
	}{
		{value: ""},
		{value: "0"},
		{value: "0d"},
		{value: "180d"},
		{value: "4320h"},
		{value: "notaduration"},
		{value: "-30d", wantErr: true},
		{value: "-1h", wantErr: true},
		{value: "-1s", wantErr: true},
	} {
		c := CleanupConfig{FTSRetention: tc.value}
		err := c.Validate()
		switch {
		case tc.wantErr && err == nil:
			t.Errorf("fts_retention = %q accepted", tc.value)
		case tc.wantErr && !strings.Contains(err.Error(), "fts_retention"):
			t.Errorf("fts_retention = %q: error %q does not name the key", tc.value, err)
		case !tc.wantErr && err != nil:
			t.Errorf("fts_retention = %q rejected: %v", tc.value, err)
		}
	}

	defaults := NewDefaultConfig().Cleanup
	if err := defaults.Validate(); err != nil {
		t.Fatalf("default [cleanup] config rejected: %v", err)
	}
}
