package imap

import (
	"testing"

	"github.com/emersion/go-imap/v2"
)

// TestUsedExtendedReturn checks the predicate behind the CLIENTBUG refusal for a
// client whose ESEARCH was filtered, with the options as go-imap's handleSearch
// passes them: a SEARCH without RETURN arrives as RETURN (ALL), as does RETURN ().
func TestUsedExtendedReturn(t *testing.T) {
	for _, tc := range []struct {
		command string
		options *imap.SearchOptions
		want    bool
	}{
		{"direct caller, nil options", nil, false},
		{"SEARCH ALL", &imap.SearchOptions{ReturnAll: true}, false},
		{"UID SEARCH UID 930:*", &imap.SearchOptions{ReturnAll: true}, false},
		{"SEARCH RETURN (ALL) ALL", &imap.SearchOptions{ReturnAll: true}, false},
		{"SEARCH RETURN () ALL", &imap.SearchOptions{ReturnAll: true}, false},
		{"SEARCH RETURN (MIN) ALL", &imap.SearchOptions{ReturnMin: true}, true},
		{"SEARCH RETURN (MAX) ALL", &imap.SearchOptions{ReturnMax: true}, true},
		{"SEARCH RETURN (MIN MAX) ALL", &imap.SearchOptions{ReturnMin: true, ReturnMax: true}, true},
		{"SEARCH RETURN (COUNT) ALL", &imap.SearchOptions{ReturnCount: true}, true},
		{"SEARCH RETURN (ALL COUNT) ALL", &imap.SearchOptions{ReturnAll: true, ReturnCount: true}, true},
		{"SEARCH RETURN (SAVE) ALL", &imap.SearchOptions{ReturnAll: true, ReturnSave: true}, true},
	} {
		if got := usedExtendedReturn(tc.options); got != tc.want {
			t.Errorf("%s: usedExtendedReturn = %v, want %v", tc.command, got, tc.want)
		}
	}
}
