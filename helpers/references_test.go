package helpers

import (
	"fmt"
	"strings"
	"testing"
)

// refID is a 62-byte message ID, numbered n, as large providers write them.
func refID(n int) string {
	return fmt.Sprintf("CAB%02d%s@mail.example.com", n, strings.Repeat("x", 40))
}

func refIDs(from, to int) []string {
	var ids []string
	for n := from; n <= to; n++ {
		ids = append(ids, refID(n))
	}
	return ids
}

// TestTrimReferences: a References field grows by one message ID per reply (RFC 5322
// §3.6.4), so in a long thread the IDs over the bound are the most recent ones, the
// parent's among them, and RFC 5256 §2.2 threads a message under "the last reference".
// The stored list was cut to its first bytes, losing those IDs and storing the last kept
// one cut short (#610). It must drop whole IDs from the middle instead, keeping the
// first and the last ones, the way RFC 5537 §3.4.4 trims References.
func TestTrimReferences(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  []string
		max  int
		want []string
	}{
		{"no references", nil, 2000, nil},
		{"under the bound, kept whole", refIDs(1, 3), 2000, refIDs(1, 3)},
		// 31 IDs of 62 bytes and 30 spaces join to exactly 1952 bytes.
		{"exactly at the bound, kept whole", refIDs(1, 31), 1952, refIDs(1, 31)},
		// 40 IDs join to 2519 bytes. The first plus the last 30 are 62 + 30*63 = 1952
		// bytes; one more would be 2015.
		{"long thread keeps the first and the last", refIDs(1, 40), 2000,
			append([]string{refID(1)}, refIDs(11, 40)...)},
		{"one byte over drops one middle ID", refIDs(1, 3), 62*3 + 2 - 1,
			[]string{refID(1), refID(3)}},
		// The first and the parent do not fit together: the parent wins.
		{"parent before root", refIDs(1, 3), 100, []string{refID(3)}},
		// An ID over the bound on its own is dropped whole, never cut.
		{"parent over the bound alone", refIDs(1, 2), 50, nil},
		{"empty and NUL-only IDs are dropped", []string{"", refID(1), "\x00", refID(2)}, 2000,
			refIDs(1, 2)},
		{"invalid UTF-8 and NULs are removed", []string{"a\x00b@example.com", "c\xffd@example.com"}, 2000,
			[]string{"ab@example.com", "cd@example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := TrimReferences(tc.ids, tc.max)
			if want := strings.Join(tc.want, " "); got != want {
				t.Errorf("TrimReferences() =\n  %q\nwant\n  %q", got, want)
			}
			if len(got) > tc.max {
				t.Errorf("TrimReferences() is %d bytes, over the bound of %d", len(got), tc.max)
			}
		})
	}
}

// TestTrimReferencesNeverCutsAnID: whatever the bound, every stored ID is one of the
// field's IDs, the list stays in order, and the parent is kept whenever it fits.
func TestTrimReferencesNeverCutsAnID(t *testing.T) {
	ids := []string{"root@example.com"}
	for n := 1; n <= 60; n++ {
		ids = append(ids, fmt.Sprintf("%s-%d@example.com", strings.Repeat("r", n%23), n))
	}
	parent := ids[len(ids)-1]
	for max := 0; max <= len(strings.Join(ids, " "))+1; max++ {
		got := TrimReferences(ids, max)
		if len(got) > max {
			t.Fatalf("max %d: %d bytes stored", max, len(got))
		}
		next := 0 // the stored IDs are a subsequence of ids
		for _, id := range strings.Fields(got) {
			for next < len(ids) && ids[next] != id {
				next++
			}
			if next == len(ids) {
				t.Fatalf("max %d: %q is not one of the field's IDs, in order: %q", max, id, got)
			}
			next++
		}
		if len(parent) <= max && !strings.HasSuffix(got, " "+parent) && got != parent {
			t.Fatalf("max %d: the parent fits but was dropped: %q", max, got)
		}
	}
}
