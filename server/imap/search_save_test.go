package imap

import (
	"slices"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
)

// RFC 5182 §2.4: SAVE stores every match with ALL or with neither MIN nor MAX,
// otherwise only the MIN and/or MAX message; COUNT never restricts it.
func TestSavedSearchSet(t *testing.T) {
	// Search's order, newest first: MIN is the last, MAX the first.
	msgs := []db.SearchMessageResult{{UID: 9}, {UID: 5}, {UID: 2}}
	minIdx, maxIdx := 2, 0

	for _, tc := range []struct {
		name    string
		options *imap.SearchOptions
		want    []imap.UID
	}{
		{"SAVE", &imap.SearchOptions{ReturnSave: true, ReturnAll: true}, []imap.UID{2, 5, 9}},
		{"SAVE COUNT", &imap.SearchOptions{ReturnSave: true, ReturnCount: true}, []imap.UID{2, 5, 9}},
		{"SAVE MIN", &imap.SearchOptions{ReturnSave: true, ReturnMin: true}, []imap.UID{2}},
		{"SAVE MAX", &imap.SearchOptions{ReturnSave: true, ReturnMax: true}, []imap.UID{9}},
		{"SAVE MIN MAX", &imap.SearchOptions{ReturnSave: true, ReturnMin: true, ReturnMax: true}, []imap.UID{2, 9}},
		{"SAVE MIN COUNT", &imap.SearchOptions{ReturnSave: true, ReturnMin: true, ReturnCount: true}, []imap.UID{2}},
		{"SAVE MIN ALL", &imap.SearchOptions{ReturnSave: true, ReturnMin: true, ReturnAll: true}, []imap.UID{2, 5, 9}},
	} {
		got, _ := savedSearchSet(msgs, minIdx, maxIdx, tc.options).Nums()
		slices.Sort(got)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: saved %v, want %v", tc.name, got, tc.want)
		}
	}

	if got := savedSearchSet(nil, -1, 0, &imap.SearchOptions{ReturnSave: true, ReturnMin: true}); len(got) != 0 {
		t.Errorf("no match: saved %v, want an empty set", got)
	}
}
