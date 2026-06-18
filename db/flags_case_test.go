package db

import (
	"reflect"
	"testing"
)

// TestFoldKeyword verifies the case-insensitive identity key for keywords.
func TestFoldKeyword(t *testing.T) {
	cases := map[string]string{
		"WAREHOUSING": "warehousing",
		"warehousing": "warehousing",
		"WareHousing": "warehousing",
		"$Junk":       "$junk",
		"":            "",
	}
	for in, want := range cases {
		if got := foldKeyword(in); got != want {
			t.Errorf("foldKeyword(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestFoldKeywordsWithMap verifies the shared-map folding primitive used to keep
// keyword case consistent across a single-mailbox import batch and a MOVE/COPY set:
// the first case seen registers as canonical and later messages fold onto it, while
// a pre-seeded map (from the mailbox cache) wins over the incoming case.
func TestFoldKeywordsWithMap(t *testing.T) {
	t.Run("first-seen wins and is shared across calls", func(t *testing.T) {
		m := map[string]string{}
		// Message 1 establishes the uppercase spelling.
		if got := foldKeywordsWithMap(m, []string{"WAREHOUSING"}); !reflect.DeepEqual(got, []string{"WAREHOUSING"}) {
			t.Fatalf("message 1: got %v", got)
		}
		// Message 2 in the same batch uses lowercase -> folds onto message 1's case.
		if got := foldKeywordsWithMap(m, []string{"warehousing"}); !reflect.DeepEqual(got, []string{"WAREHOUSING"}) {
			t.Errorf("message 2: got %v, want [WAREHOUSING]", got)
		}
	})

	t.Run("pre-seeded canonical from cache wins", func(t *testing.T) {
		m := map[string]string{"warehousing": "warehousing"} // seeded from mailbox cache
		if got := foldKeywordsWithMap(m, []string{"WAREHOUSING"}); !reflect.DeepEqual(got, []string{"warehousing"}) {
			t.Errorf("got %v, want [warehousing]", got)
		}
	})

	t.Run("intra-slice case duplicates collapse", func(t *testing.T) {
		m := map[string]string{}
		if got := foldKeywordsWithMap(m, []string{"Foo", "foo", "Bar"}); !reflect.DeepEqual(got, []string{"Bar", "Foo"}) {
			t.Errorf("got %v, want [Bar Foo]", got)
		}
	})

	t.Run("empty input returns empty", func(t *testing.T) {
		if got := foldKeywordsWithMap(map[string]string{}, []string{}); len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
	})
}

// TestDedupKeywordsByFold verifies that case-variants of the same keyword collapse
// to a single, deterministic representative while order is otherwise preserved.
func TestDedupKeywordsByFold(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "collapse two cases keeps lexicographically smallest",
			// "WAREHOUSING" < "warehousing" in ASCII (uppercase before lowercase).
			in:   []string{"warehousing", "WAREHOUSING"},
			want: []string{"WAREHOUSING"},
		},
		{
			name: "base keyword case collapse",
			in:   []string{"$Junk", "$junk", "Work"},
			want: []string{"$Junk", "Work"},
		},
		{
			name: "no duplicates passes through unchanged",
			in:   []string{"Alpha", "Beta", "Gamma"},
			want: []string{"Alpha", "Beta", "Gamma"},
		},
		{
			name: "single element unchanged",
			in:   []string{"Solo"},
			want: []string{"Solo"},
		},
		{
			name: "empty unchanged",
			in:   []string{},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dedupKeywordsByFold(tt.in)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("dedupKeywordsByFold(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
