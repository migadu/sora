package imap

import (
	"fmt"
	"testing"

	"github.com/emersion/go-imap/v2"
)

// TestRecentAsUIDs: go-imap passes SEARCH RECENT as Flag \Recent, OLD as
// NotFlag \Recent and NEW as both Flag \Recent and NotFlag \Seen; each becomes
// the session's recent UID set, nested keys included.
func TestRecentAsUIDs(t *testing.T) {
	recent := imap.UIDSet{{Start: 5, Stop: 4294967295}}
	uid1 := imap.UIDSet{{Start: 1, Stop: 1}}

	for _, tc := range []struct {
		name string
		in   imap.SearchCriteria
		want imap.SearchCriteria
	}{
		{
			name: "RECENT",
			in:   imap.SearchCriteria{Flag: []imap.Flag{"\\Recent"}},
			want: imap.SearchCriteria{UID: []imap.UIDSet{recent}},
		},
		{
			name: "OLD",
			in:   imap.SearchCriteria{NotFlag: []imap.Flag{"\\Recent"}},
			want: imap.SearchCriteria{Not: []imap.SearchCriteria{{UID: []imap.UIDSet{recent}}}},
		},
		{
			name: "NEW",
			in:   imap.SearchCriteria{Flag: []imap.Flag{"\\Recent"}, NotFlag: []imap.Flag{imap.FlagSeen}},
			want: imap.SearchCriteria{UID: []imap.UIDSet{recent}, NotFlag: []imap.Flag{imap.FlagSeen}},
		},
		{
			name: "any case, other keys kept",
			in:   imap.SearchCriteria{UID: []imap.UIDSet{uid1}, Flag: []imap.Flag{imap.FlagFlagged, "\\RECENT"}},
			want: imap.SearchCriteria{UID: []imap.UIDSet{uid1, recent}, Flag: []imap.Flag{imap.FlagFlagged}},
		},
		{
			name: "inside NOT and OR",
			in: imap.SearchCriteria{
				Not: []imap.SearchCriteria{{Flag: []imap.Flag{"\\Recent"}}},
				Or:  [][2]imap.SearchCriteria{{{NotFlag: []imap.Flag{"\\Recent"}}, {UID: []imap.UIDSet{uid1}}}},
			},
			want: imap.SearchCriteria{
				Not: []imap.SearchCriteria{{UID: []imap.UIDSet{recent}}},
				Or: [][2]imap.SearchCriteria{{
					{Not: []imap.SearchCriteria{{UID: []imap.UIDSet{recent}}}},
					{UID: []imap.UIDSet{uid1}},
				}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := fmt.Sprintf("%+v", tc.in)
			if !mentionsRecent(&tc.in) {
				t.Fatalf("mentionsRecent(%s) = false", before)
			}
			// %+v prints a nil and an empty slice alike, which DeepEqual does not.
			got := recentAsUIDs(&tc.in, recent)
			if g, w := fmt.Sprintf("%+v", *got), fmt.Sprintf("%+v", tc.want); g != w {
				t.Errorf("got  %s\nwant %s", g, w)
			}
			if after := fmt.Sprintf("%+v", tc.in); after != before {
				t.Errorf("input modified:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

func TestMentionsRecent_None(t *testing.T) {
	c := imap.SearchCriteria{
		Flag:    []imap.Flag{imap.FlagSeen, "$Recent"},
		NotFlag: []imap.Flag{imap.FlagDeleted},
		Not:     []imap.SearchCriteria{{Flag: []imap.Flag{imap.FlagDraft}}},
		Or:      [][2]imap.SearchCriteria{{{Flag: []imap.Flag{imap.FlagFlagged}}, {}}},
	}
	if mentionsRecent(&c) {
		t.Errorf("mentionsRecent(%+v) = true", c)
	}
}
