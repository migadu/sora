package helpers

import (
	"slices"
	"testing"

	"github.com/emersion/go-message/mail"
)

func groupStart(typ, name string) Recipient { return Recipient{AddressType: typ, Group: name} }
func groupEnd(typ string) Recipient         { return Recipient{AddressType: typ, GroupEnd: true} }
func addr(typ, email, name string) Recipient {
	return Recipient{AddressType: typ, EmailAddress: email, Name: name}
}

// TestExtractRecipientsAddressGroups checks that RFC 5322 §3.4 groups keep their name and
// bounds (#2012): IMAP ENVELOPE reports them as group start/end addresses (RFC 3501
// §7.4.2), and an empty group is a start directly followed by its end.
func TestExtractRecipientsAddressGroups(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  []Recipient
	}{
		{
			// imaptest fetch-envelope.mbox, message 4.
			name:  "two groups",
			value: "group: g1@d1.org, g2@d2.org;, group2: g3@d3.org;",
			want: []Recipient{
				groupStart("to", "group"), addr("to", "g1@d1.org", ""), addr("to", "g2@d2.org", ""), groupEnd("to"),
				groupStart("to", "group2"), addr("to", "g3@d3.org", ""), groupEnd("to"),
			},
		},
		{
			name:  "empty groups, one holding only a comment",
			value: "group:;, group2: (foo) ;",
			want:  []Recipient{groupStart("to", "group"), groupEnd("to"), groupStart("to", "group2"), groupEnd("to")},
		},
		{
			name:  "undisclosed-recipients",
			value: "undisclosed-recipients:;",
			want:  []Recipient{groupStart("to", "undisclosed-recipients"), groupEnd("to")},
		},
		{
			name:  "addresses around a group",
			value: "Plain <plain@example.com>, team: a@example.com, B <b@example.com>;, last@example.com",
			want: []Recipient{
				addr("to", "plain@example.com", "Plain"),
				groupStart("to", "team"), addr("to", "a@example.com", ""), addr("to", "b@example.com", "B"), groupEnd("to"),
				addr("to", "last@example.com", ""),
			},
		},
		{
			name:  "quoted, commented and encoded group names",
			value: `"Team: A" (x) :a@example.com;, =?utf-8?q?Caf=C3=A9?= list:;`,
			want: []Recipient{
				groupStart("to", "Team: A"), addr("to", "a@example.com", ""), groupEnd("to"),
				groupStart("to", "Café list"), groupEnd("to"),
			},
		},
		{
			name:  "colon in a display name or a route is no group",
			value: `"Re: x" <a@example.com>, b@example.com (c: d)`,
			want:  []Recipient{addr("to", "a@example.com", "Re: x"), addr("to", "b@example.com", "c: d")},
		},
		{
			// The list is the header as written (#2079): each group keeps its members.
			name:  "an address in two groups is in both",
			value: "g: a@example.com;, h: a@example.com;",
			want: []Recipient{
				groupStart("to", "g"), addr("to", "a@example.com", ""), groupEnd("to"),
				groupStart("to", "h"), addr("to", "a@example.com", ""), groupEnd("to"),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractRecipients(mail.HeaderFromMap(map[string][]string{"To": {tc.value}}).Header)
			if !slices.Equal(got, tc.want) {
				t.Errorf("ExtractRecipients(To: %s)\n got %+v\nwant %+v", tc.value, got, tc.want)
			}
		})
	}
}

// TestExtractRecipientsMalformedGroupsParseFlat checks that a value that is not well
// formed group syntax keeps the flat mail.ParseAddressList result it had before groups
// were kept.
func TestExtractRecipientsMalformedGroupsParseFlat(t *testing.T) {
	for _, value := range []string{
		"g: a@example.com",                  // unterminated
		"g: h: a@example.com;;",             // nested
		"a@example.com; b@example.com",      // ';' outside a group
		": a@example.com;",                  // no group name
		"g: not an address;, b@example.com", // a member that does not parse
	} {
		t.Run(value, func(t *testing.T) {
			var want []Recipient
			if list, err := mail.ParseAddressList(value); err == nil {
				for _, a := range list {
					want = append(want, addr("to", a.Address, a.Name))
				}
			}
			got := ExtractRecipients(mail.HeaderFromMap(map[string][]string{"To": {value}}).Header)
			if len(got) != len(want) || (len(want) > 0 && !slices.Equal(got, want)) {
				t.Errorf("ExtractRecipients(To: %s) = %+v, want the flat parse %+v", value, got, want)
			}
			for _, r := range got {
				if r.IsGroupMarker() {
					t.Errorf("ExtractRecipients(To: %s): unexpected group marker %+v", value, r)
				}
			}
		})
	}
}
