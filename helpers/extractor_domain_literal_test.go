package helpers

import (
	"slices"
	"testing"

	"github.com/emersion/go-message"
)

// Colons in a bare IPv6 domain literal are part of its address, including when
// that address precedes or belongs to a group. They must not flatten the groups.
func TestExtractRecipientsGroupsWithDomainLiterals(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  []Recipient
	}{
		{"outside@[2001:db8::1], team: inside@example.com;", []Recipient{
			addr("to", "outside@[2001:db8::1]", ""), groupStart("to", "team"), addr("to", "inside@example.com", ""), groupEnd("to"),
		}},
		{"team: inside (comment)@ (comment) example.com;", []Recipient{
			groupStart("to", "team"), addr("to", "inside@example.com", ""), groupEnd("to"),
		}},
		{"team: inside@[2001:db8::1];", []Recipient{
			groupStart("to", "team"), addr("to", "inside@[2001:db8::1]", ""), groupEnd("to"),
		}},
		{`outside@[::1] (a comment:;), "A:B": <inside@[2001:db8::2]>;, tail@[::3]`, []Recipient{
			addr("to", "outside@[::1]", "a comment:;"), groupStart("to", "A:B"), addr("to", "inside@[2001:db8::2]", ""), groupEnd("to"), addr("to", "tail@[::3]", ""),
		}},
	} {
		t.Run(tc.value, func(t *testing.T) {
			var h message.Header
			h.Set("To", tc.value)
			if got := ExtractRecipients(h); !slices.Equal(got, tc.want) {
				t.Fatalf("ExtractRecipients(%q) = %+v, want %+v", tc.value, got, tc.want)
			}
		})
	}
}

// An escaped closing bracket or an unterminated literal must not turn the
// following colon into a group delimiter. The normal parser rejects these.
func TestExtractRecipientsMalformedDomainLiteralDoesNotCreateGroups(t *testing.T) {
	for _, value := range []string{
		`outside@[2001:db8::1, team: inside@example.com;`,
		`outside@[2001:db8::1\], team: inside@example.com;`,
	} {
		var h message.Header
		h.Set("To", value)
		if got := ExtractRecipients(h); len(got) != 0 {
			t.Errorf("ExtractRecipients(%q) = %+v, want no addresses", value, got)
		}
	}
}
