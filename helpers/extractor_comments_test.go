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

// TestExtractRecipientsUnterminatedComment: a header cut off inside a comment keeps the
// complete addresses, and groups, before it: the unclosed comment and everything after it
// are dropped. A comment left open before an address is finished leaves no address, as
// before. ParseAddressList, for the same header as written, gives the same addresses.
func TestExtractRecipientsUnterminatedComment(t *testing.T) {
	to := func(email, name string) Recipient {
		return Recipient{AddressType: "to", EmailAddress: email, Name: name}
	}
	for _, tc := range []struct {
		value string
		want  []Recipient
	}{
		{"user@example.com (unterminated", []Recipient{to("user@example.com", "")}},
		{"a@example.com, b@example.com (unclosed", []Recipient{to("a@example.com", ""), to("b@example.com", "")}},
		{"team: a@example.com; (unterminated", []Recipient{
			{AddressType: "to", Group: "team"}, to("a@example.com", ""), {AddressType: "to", GroupEnd: true}}},
		{"undisclosed-recipients:; (cut", []Recipient{{AddressType: "to", Group: "undisclosed-recipients"}, {AddressType: "to", GroupEnd: true}}},
		{"<user (c) @ example.com> (unclosed", []Recipient{to("user@example.com", "")}},
		{`"user (team)"@example.com (unclosed`, []Recipient{to("user (team)@example.com", "")}},
		{"a@example.com (open, b@example.com", []Recipient{to("a@example.com", "")}},
		{"<@route:user@example.com> (open", []Recipient{{AddressType: "to", EmailAddress: "user@example.com", Route: "@route"}}},
		// A closed comment before the cut is the display name it is in the header without
		// the cut, "c@example.com (closed)". (Sora's own parser used to drop it here: its
		// fallback for an unclosed comment removed every comment.)
		{"A <a@example.com>, team: b@example.com;, c@example.com (closed) (open", []Recipient{
			to("a@example.com", "A"), {AddressType: "to", Group: "team"}, to("b@example.com", ""), {AddressType: "to", GroupEnd: true},
			to("c@example.com", "closed")}},
		// The comment opens before an address is complete.
		{"team: a@example.com (open;", nil},
		{"Name (open <user@example.com>", nil},
		{"<user@example.com (open>", nil},
	} {
		t.Run(tc.value, func(t *testing.T) {
			var h message.Header
			h.Set("To", tc.value)
			got := ExtractRecipients(h)
			if len(got) != len(tc.want) || (len(got) > 0 && !slices.Equal(got, tc.want)) {
				t.Errorf("ExtractRecipients(To: %s)\n got %+v\nwant %+v", tc.value, got, tc.want)
			}
			var want []string
			for _, r := range tc.want {
				if !r.IsGroupMarker() {
					want = append(want, r.EmailAddress)
				}
			}
			list, _ := ParseAddressList(tc.value)
			var addresses []string
			for _, a := range list {
				addresses = append(addresses, a.Address)
			}
			if !slices.Equal(addresses, want) {
				t.Errorf("ParseAddressList(%s) = %q, want %q", tc.value, addresses, want)
			}
		})
	}
}
