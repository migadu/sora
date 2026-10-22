package imap

import (
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func uidRange(start, stop imap.UID) imap.UIDSet {
	return imap.UIDSet{imap.UIDRange{Start: start, Stop: stop}}
}

func seqRange(start, stop uint32) imap.SeqSet {
	return imap.SeqSet{imap.SeqRange{Start: start, Stop: stop}}
}

// The commands the search rate limit charges, and the ones it lets through,
// including those a webmail client sends while a user clicks through their mail.
func TestSearchRateLimitCharges(t *testing.T) {
	from := imap.SearchCriteriaHeaderField{Key: "From", Value: "alice"}
	ref := imap.SearchCriteriaHeaderField{Key: "References", Value: "abc@example.com"}

	cases := []struct {
		name         string
		criteria     *imap.SearchCriteria
		search       bool // SEARCH is charged
		sortOrThread bool // SORT and THREAD are charged
	}{
		{"ALL", &imap.SearchCriteria{}, false, true},
		{"nil criteria", nil, false, true},
		{"UID set after a MOVE", &imap.SearchCriteria{UID: []imap.UIDSet{uidRange(10, 60)}}, false, false},
		{"UNSEEN", &imap.SearchCriteria{NotFlag: []imap.Flag{imap.FlagSeen}}, false, true},
		{"keyword, date and size", &imap.SearchCriteria{
			Flag:  []imap.Flag{"$Important"},
			Since: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Larger: 1000,
		}, false, true},
		{"MODSEQ", &imap.SearchCriteria{ModSeq: &imap.SearchCriteriaModSeq{ModSeq: 5}}, false, true},
		{"one page of UIDs", &imap.SearchCriteria{UID: []imap.UIDSet{{
			imap.UIDRange{Start: 3, Stop: 3}, imap.UIDRange{Start: 9, Stop: 40}, imap.UIDRange{Start: 77, Stop: 80},
		}}}, false, false},
		{"sequence range", &imap.SearchCriteria{SeqNum: []imap.SeqSet{seqRange(1, 500)}}, false, false},
		{"reversed range", &imap.SearchCriteria{UID: []imap.UIDSet{uidRange(500, 1)}}, false, false},
		{"set at the limit", &imap.SearchCriteria{UID: []imap.UIDSet{uidRange(1, confinedMaxMessages)}}, false, false},
		{"set over the limit", &imap.SearchCriteria{UID: []imap.UIDSet{uidRange(1, confinedMaxMessages+1)}}, false, true},
		{"ranges adding up over the limit", &imap.SearchCriteria{UID: []imap.UIDSet{{
			imap.UIDRange{Start: 1, Stop: 600}, imap.UIDRange{Start: 1001, Stop: 1600},
		}}}, false, true},
		{"UID 1:4294967295", &imap.SearchCriteria{UID: []imap.UIDSet{uidRange(1, 4294967295)}}, false, true},
		{"UID 1:*", &imap.SearchCriteria{UID: []imap.UIDSet{uidRange(1, 0)}}, false, true},
		{"sequence 1:*", &imap.SearchCriteria{SeqNum: []imap.SeqSet{seqRange(1, 0)}}, false, true},
		{"saved result $", &imap.SearchCriteria{UID: []imap.UIDSet{imap.SearchRes()}}, false, true},
		{"a large set and a small one", &imap.SearchCriteria{UID: []imap.UIDSet{uidRange(1, 0), uidRange(5, 9)}}, false, false},
		{"small set under OR confines nothing", &imap.SearchCriteria{Or: [][2]imap.SearchCriteria{{
			{UID: []imap.UIDSet{uidRange(1, 5)}}, {Flag: []imap.Flag{imap.FlagFlagged}},
		}}}, false, true},
		{"small set under NOT confines nothing", &imap.SearchCriteria{Not: []imap.SearchCriteria{
			{UID: []imap.UIDSet{uidRange(1, 5)}},
		}}, false, true},
		{"FROM", &imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{from}}, true, true},
		{"BODY", &imap.SearchCriteria{Body: []string{"invoice"}}, true, true},
		{"TEXT", &imap.SearchCriteria{Text: []string{"invoice"}}, true, true},
		{"FROM confined to a page", &imap.SearchCriteria{
			UID:    []imap.UIDSet{uidRange(1, 50)},
			Header: []imap.SearchCriteriaHeaderField{from},
		}, true, true},
		{"BODY under NOT", &imap.SearchCriteria{Not: []imap.SearchCriteria{{Body: []string{"spam"}}}}, true, true},
		{"HEADER deep in ORs", &imap.SearchCriteria{Or: [][2]imap.SearchCriteria{{
			{Flag: []imap.Flag{imap.FlagSeen}},
			{Or: [][2]imap.SearchCriteria{{{Larger: 10}, {Header: []imap.SearchCriteriaHeaderField{ref}}}}},
		}}}, true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := criteriaMatchesContent(tc.criteria); got != tc.search {
				t.Errorf("SEARCH charged = %v, want %v", got, tc.search)
			}
			if got := scanCharged(tc.criteria); got != tc.sortOrThread {
				t.Errorf("SORT/THREAD charged = %v, want %v", got, tc.sortOrThread)
			}
		})
	}
}
