package helpers

import (
	"slices"
	"testing"

	"github.com/emersion/go-message"
)

// TestExtractRecipientsAddressComments: RFC 5322 §3.4.1 makes local-part and domain
// dot-atoms, and a dot-atom may have CFWS (comments and folding white space) on either
// side, so the "@" of an addr-spec can be surrounded by comments. net/mail rejects that,
// and ExtractRecipients used to drop the whole header, which lost the address from SEARCH
// FROM and from the ENVELOPE (#2014). Headers net/mail already parses must come out as
// before, including a trailing comment taken as the display name.
func TestExtractRecipientsAddressComments(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  []Recipient
	}{
		{"imaptest search-addresses message 3", "<user-from (comment)@ (comment) domain.org>",
			[]Recipient{{EmailAddress: "user-from@domain.org", AddressType: "from"}}},
		{"bare addr-spec with comments", "user-from (comment)@ (comment) domain.org",
			[]Recipient{{EmailAddress: "user-from@domain.org", AddressType: "from"}}},
		{"display name kept", "Real Name <user (c) @ example.com>",
			[]Recipient{{EmailAddress: "user@example.com", AddressType: "from", Name: "Real Name"}}},
		{"comment inside the angle brackets after the domain", "<user@example.com (c)>",
			[]Recipient{{EmailAddress: "user@example.com", AddressType: "from"}}},
		{"nested comment and escaped paren", "<user (a (b) \\) c)@example.com>",
			[]Recipient{{EmailAddress: "user@example.com", AddressType: "from"}}},
		{"other addresses of the list kept", "a@example.com, <b (c)@example.org>",
			[]Recipient{{EmailAddress: "a@example.com", AddressType: "from"}, {EmailAddress: "b@example.org", AddressType: "from"}}},
		{"quoted local part keeps its parens and at-sign", `"x (y) @z" (c) @ example.com`,
			[]Recipient{{EmailAddress: "x (y) @z@example.com", AddressType: "from"}}},
		{"unchanged: trailing comment is the name", "user-from@domain.org (RealFrom)",
			[]Recipient{{EmailAddress: "user-from@domain.org", AddressType: "from", Name: "RealFrom"}}},
		{"unchanged: plain name-addr", "RealFrom <user-from@domain.org>",
			[]Recipient{{EmailAddress: "user-from@domain.org", AddressType: "from", Name: "RealFrom"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var h message.Header
			h.Set("From", tc.value)
			got := ExtractRecipients(h)
			if !slices.Equal(got, tc.want) {
				t.Errorf("ExtractRecipients(From: %s) = %+v, want %+v", tc.value, got, tc.want)
			}
		})
	}
}
