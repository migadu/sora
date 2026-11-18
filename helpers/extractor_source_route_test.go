package helpers

import (
	"slices"
	"testing"

	"github.com/emersion/go-message/mail"
)

// RFC 5322 section 4.4 requires parsing obsolete angle-addr routes, while the
// route itself is ignored. The final mailbox and display name remain usable.
func TestParseAddressListObsoleteSourceRoutes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  []mail.Address
	}{
		{"imaptest envelope", "<@route:user@domain>", []mail.Address{{Address: "user@domain"}}},
		{"multiple hops", "<@first,@second:user@domain>", []mail.Address{{Address: "user@domain"}}},
		{"display name", "Real Name <@route:user@domain>", []mail.Address{{Name: "Real Name", Address: "user@domain"}}},
		{"encoded display name", "=?utf-8?q?Caf=C3=A9?= <@route:user@domain>", []mail.Address{{Name: "Café", Address: "user@domain"}}},
		{"comments and mailbox CFWS", "Real Name < (before) @first (hop) , (between) @second : user (local) @ domain >", []mail.Address{{Name: "Real Name", Address: "user@domain"}}},
		{"comments in hop domain", "<@first (c) . (c) example, @second:user@domain>", []mail.Address{{Address: "user@domain"}}},
		{"folding white space", "<\r\n @first,\r\n\t@second:user@domain>", []mail.Address{{Address: "user@domain"}}},
		{"empty route elements", "<, (before) , @first,, (between) @second, :user@domain>", []mail.Address{{Address: "user@domain"}}},
		{"domain literals", "<@[2001:db8::1],@[192.0.2.1]:user@[2001:db8::2]>", []mail.Address{{Address: "user@[2001:db8::2]"}}},
		{"quoted pair in hop literal", `<@[x\]y]:user@domain>`, []mail.Address{{Address: "user@domain"}}},
		{"quoted local part", `<@route:"x:y@z"@domain>`, []mail.Address{{Address: "x:y@z@domain"}}},
		{"quoted display name route text", `"Name: <@fake:other@domain>" <@route:user@domain>`, []mail.Address{{Name: "Name: <@fake:other@domain>", Address: "user@domain"}}},
		{"comment route text", "Name (not <@fake:other@domain>) <@route:user@domain>", []mail.Address{{Name: "Name", Address: "user@domain"}}},
		{"mixed list", "plain@domain, <@first:one@domain>, <@second:two@domain>", []mail.Address{{Address: "plain@domain"}, {Address: "one@domain"}, {Address: "two@domain"}}},
		{"group", "team: <@first:one@domain>, <@second:two@domain>;", []mail.Address{{Address: "one@domain"}, {Address: "two@domain"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseAddressList(tc.value)
			if err != nil {
				t.Fatalf("ParseAddressList(%q): %v", tc.value, err)
			}
			var got []mail.Address
			for _, address := range parsed {
				got = append(got, *address)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("ParseAddressList(%q) = %+v, want %+v", tc.value, got, tc.want)
			}
		})
	}
}

// Stripping an arbitrary angle-addr prefix at ':' would accidentally accept
// malformed routes. Validate every hop and leave final mailbox checks to mail.
func TestParseAddressListRejectsMalformedSourceRoutes(t *testing.T) {
	for _, value := range []string{
		"<@:user@domain>",
		"<route:user@domain>",
		"<@first,second:user@domain>",
		"<@first @second:user@domain>",
		"<@first..example:user@domain>",
		"<@first.:user@domain>",
		"<@first words:user@domain>",
		"<@first;:user@domain>",
		"<@\"first\":user@domain>",
		"<@first:user@domain",
		"<@first:>",
		"<@first:not-an-address>",
		"<@first:other:user@domain>",
		"<@first (unfinished:user@domain>",
		"<@[unfinished:user@domain>",
		"<@[escaped\\]:user@domain>",
		"<@first\n:user@domain>",
		"<@first\r\n:user@domain>",
	} {
		t.Run(value, func(t *testing.T) {
			if got, err := ParseAddressList(value); err == nil {
				t.Fatalf("ParseAddressList(%q) = %+v, want an error", value, got)
			}
		})
	}
}

func TestExtractRecipientsSourceRoutesInEveryHeader(t *testing.T) {
	h := mail.HeaderFromMap(map[string][]string{
		"To":       {"Name <@first,@second:user@domain>"},
		"Cc":       {"Name <@first,@second:user@domain>"},
		"Bcc":      {"Name <@first,@second:user@domain>"},
		"From":     {"Name <@first,@second:user@domain>"},
		"Sender":   {"Name <@first,@second:user@domain>"},
		"Reply-To": {"Name <@first,@second:user@domain>"},
	})
	var want []Recipient
	for _, typ := range []string{"to", "cc", "bcc", "from", "sender", "reply-to"} {
		want = append(want, Recipient{AddressType: typ, EmailAddress: "user@domain", Name: "Name"})
	}
	if got := ExtractRecipients(h.Header); !slices.Equal(got, want) {
		t.Fatalf("ExtractRecipients = %+v, want %+v", got, want)
	}
}

func TestExtractRecipientsSourceRoutesKeepGroupBoundaries(t *testing.T) {
	for _, value := range []string{
		"Team: <@route:user@domain>;",
		"Team: <@route (not > end):user@domain>;",
		"Team: <@[route>literal]:user@domain>;",
	} {
		t.Run(value, func(t *testing.T) {
			h := mail.HeaderFromMap(map[string][]string{"To": {value}})
			want := []Recipient{
				{AddressType: "to", Group: "Team"},
				{AddressType: "to", EmailAddress: "user@domain"},
				{AddressType: "to", GroupEnd: true},
			}
			if got := ExtractRecipients(h.Header); !slices.Equal(got, want) {
				t.Fatalf("ExtractRecipients(%q) = %+v, want %+v", value, got, want)
			}
		})
	}
}
