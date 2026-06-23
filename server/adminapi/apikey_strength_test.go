package adminapi

import (
	"strings"
	"testing"
)

// TestNew_RejectsWeakAPIKey verifies the Admin API refuses to start with a missing
// or too-short API key (audit H6). The key check runs before any DB use, so New can
// be called with a nil rdb here.
func TestNew_RejectsWeakAPIKey(t *testing.T) {
	cases := []struct{ name, key, wantErr string }{
		{"empty", "", "required"},
		{"too short", "short-key", "at least"},
		{"15 chars", strings.Repeat("a", 15), "at least"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(nil, ServerOptions{APIKey: c.key})
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("APIKey=%q: got err=%v, want substring %q", c.key, err, c.wantErr)
			}
		})
	}
}
