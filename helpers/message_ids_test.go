package helpers

import (
	"slices"
	"strings"
	"testing"

	"github.com/emersion/go-message/mail"
)

func TestSplitMessageIDsParsedStorage(t *testing.T) {
	for _, id := range []string{
		"non\u00a0breaking@example.com",
		"em\u2003part@dom\u00a0ain.example",
		`literal@[<inner>]`,
		`"quoted local"@[<inner>]`,
		`literal@["<inner>"]`,
		"literal@[non\u00a0breaking]",
		`"a\" b"@example.com`,
	} {
		t.Run(id, func(t *testing.T) {
			h := mail.HeaderFromMap(map[string][]string{"In-Reply-To": {"<" + id + "> <next@example.com>"}})
			parsed, err := h.MsgIDList("In-Reply-To")
			if err != nil {
				t.Fatalf("MsgIDList: %v", err)
			}
			want := []string{id, "next@example.com"}
			if !slices.Equal(parsed, want) {
				t.Fatalf("parsed ids = %q, want %q", parsed, want)
			}
			stored := strings.Join(parsed, " ")
			if got := SplitMessageIDs(stored); !slices.Equal(got, want) {
				t.Fatalf("SplitMessageIDs(%q) = %q, want %q", stored, got, want)
			}
		})
	}
}
