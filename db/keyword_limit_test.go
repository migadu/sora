package db

import (
	"fmt"
	"testing"

	"github.com/emersion/go-imap/v2"
)

func TestDistinctKeywordCount(t *testing.T) {
	cases := []struct {
		name  string
		flags []imap.Flag
		want  int
	}{
		{"empty", nil, 0},
		{"only system flags", []imap.Flag{imap.FlagSeen, imap.FlagDeleted}, 0},
		{"system + custom", []imap.Flag{imap.FlagSeen, "$Work", "$Personal"}, 2},
		{"case folds to one", []imap.Flag{"Work", "WORK", "work"}, 1},
		{"exact duplicates", []imap.Flag{"$Label1", "$Label1"}, 1},
		{"mixed case and dupes", []imap.Flag{imap.FlagFlagged, "Tag", "TAG", "$Other"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DistinctKeywordCount(tc.flags); got != tc.want {
				t.Errorf("DistinctKeywordCount(%v) = %d, want %d", tc.flags, got, tc.want)
			}
		})
	}
}

func TestCapCustomKeywords(t *testing.T) {
	mk := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("kw-%03d", i)
		}
		return out
	}

	t.Run("under limit unchanged", func(t *testing.T) {
		in := mk(MaxCustomKeywordsPerMessage - 1)
		got := capCustomKeywords(in)
		if len(got) != len(in) {
			t.Fatalf("len = %d, want %d", len(got), len(in))
		}
	})

	t.Run("at limit unchanged", func(t *testing.T) {
		in := mk(MaxCustomKeywordsPerMessage)
		got := capCustomKeywords(in)
		if len(got) != MaxCustomKeywordsPerMessage {
			t.Fatalf("len = %d, want %d", len(got), MaxCustomKeywordsPerMessage)
		}
	})

	t.Run("over limit truncates preserving order", func(t *testing.T) {
		in := mk(MaxCustomKeywordsPerMessage + 25)
		got := capCustomKeywords(in)
		if len(got) != MaxCustomKeywordsPerMessage {
			t.Fatalf("len = %d, want %d", len(got), MaxCustomKeywordsPerMessage)
		}
		for i, kw := range got {
			if kw != in[i] {
				t.Fatalf("element %d = %q, want %q (order must be preserved)", i, kw, in[i])
			}
		}
	})
}
