package helpers

import (
	"encoding/json"
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
		want = append(want, Recipient{AddressType: typ, EmailAddress: "user@domain", Name: "Name", Route: "@first,@second"})
	}
	if got := ExtractRecipients(h.Header); !slices.Equal(got, want) {
		t.Fatalf("ExtractRecipients = %+v, want %+v", got, want)
	}
}

func TestExtractRecipientsSourceRoutesKeepGroupBoundaries(t *testing.T) {
	for _, tc := range []struct{ value, route string }{
		{"Team: <@route:user@domain>;", "@route"},
		{"Team: <@route (not > end):user@domain>;", "@route"},
		{"Team: <@[route>literal]:user@domain>;", "@[route>literal]"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			h := mail.HeaderFromMap(map[string][]string{"To": {tc.value}})
			want := []Recipient{
				{AddressType: "to", Group: "Team"},
				{AddressType: "to", EmailAddress: "user@domain", Route: tc.route},
				{AddressType: "to", GroupEnd: true},
			}
			if got := ExtractRecipients(h.Header); !slices.Equal(got, want) {
				t.Fatalf("ExtractRecipients(%q) = %+v, want %+v", tc.value, got, want)
			}
		})
	}
}

// TestExtractRecipientsSourceRouteCanonicalForm: the route is kept for the ENVELOPE's
// addr-adl (RFC 9051 §7.5.2) in the form Dovecot reports: every hop as "@" domain,
// joined by ",", without comments, folding or empty list elements (#2119). The address
// itself is unchanged, and an address without a route has none.
func TestExtractRecipientsSourceRouteCanonicalForm(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        []Recipient
	}{
		{"imaptest fetch-envelope", "<@route:user@domain>", []Recipient{{EmailAddress: "user@domain", Route: "@route"}}},
		{"multiple hops", "<@first,@second:user@domain>", []Recipient{{EmailAddress: "user@domain", Route: "@first,@second"}}},
		{"comments and mailbox CFWS", "Real Name < (before) @first (hop) , (between) @second : user (local) @ domain >",
			[]Recipient{{Name: "Real Name", EmailAddress: "user@domain", Route: "@first,@second"}}},
		{"comments in hop domain", "<@first (c) . (c) example, @second:user@domain>", []Recipient{{EmailAddress: "user@domain", Route: "@first.example,@second"}}},
		{"folding white space", "<\r\n @first,\r\n\t@second:user@domain>", []Recipient{{EmailAddress: "user@domain", Route: "@first,@second"}}},
		{"empty route elements", "<, (before) , @first,, (between) @second, :user@domain>", []Recipient{{EmailAddress: "user@domain", Route: "@first,@second"}}},
		{"domain literals", "<@[2001:db8::1],@[192.0.2.1]:user@[2001:db8::2]>", []Recipient{{EmailAddress: "user@[2001:db8::2]", Route: "@[2001:db8::1],@[192.0.2.1]"}}},
		{"quoted local part", `<@route:"x:y@z"@domain>`, []Recipient{{EmailAddress: "x:y@z@domain", Route: "@route"}}},
		{"route text in a quoted display name", `"Name: <@fake:other@domain>" <@route:user@domain>`,
			[]Recipient{{Name: "Name: <@fake:other@domain>", EmailAddress: "user@domain", Route: "@route"}}},
		{"each route stays with its address", "plain@domain,, <@first:one@domain>, Two <two@domain>, <@second,@third:three@domain>", []Recipient{
			{EmailAddress: "plain@domain"}, {EmailAddress: "one@domain", Route: "@first"},
			{Name: "Two", EmailAddress: "two@domain"}, {EmailAddress: "three@domain", Route: "@second,@third"}}},
		{"group members and the addresses around the group", "<@a:before@domain>, team: one@domain, <@b:two@domain>;, <@c:after@domain>", []Recipient{
			{EmailAddress: "before@domain", Route: "@a"}, {Group: "team"}, {EmailAddress: "one@domain"},
			{EmailAddress: "two@domain", Route: "@b"}, {GroupEnd: true}, {EmailAddress: "after@domain", Route: "@c"}}},
		{"no route", "Plain <user@domain>, other@domain", []Recipient{{Name: "Plain", EmailAddress: "user@domain"}, {EmailAddress: "other@domain"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := mail.HeaderFromMap(map[string][]string{"Cc": {tc.value}})
			want := slices.Clone(tc.want)
			for i := range want {
				want[i].AddressType = "cc"
			}
			if got := ExtractRecipients(h.Header); !slices.Equal(got, want) {
				t.Fatalf("ExtractRecipients(%q)\n got %+v\nwant %+v", tc.value, got, want)
			}
		})
	}
}

// TestSourceRouteIsNotPartOfTheAddress: only the ENVELOPE reports the route. The
// recipients of a delivery and the distinct address lists do not see it, a routed and a
// plain spelling of one address are one address.
func TestSourceRouteIsNotPartOfTheAddress(t *testing.T) {
	h := mail.HeaderFromMap(map[string][]string{"To": {"<@route:user@domain>, user@domain, <@other:second@domain>"}})
	if got, want := ExtractEnvelopeRecipients(h.Header), []string{"user@domain", "second@domain"}; !slices.Equal(got, want) {
		t.Errorf("ExtractEnvelopeRecipients = %q, want %q", got, want)
	}
	distinct := DistinctAddresses(ExtractRecipients(h.Header))
	want := []Recipient{{AddressType: "to", EmailAddress: "user@domain", Route: "@route"}, {AddressType: "to", EmailAddress: "second@domain", Route: "@other"}}
	if !slices.Equal(distinct, want) {
		t.Errorf("DistinctAddresses = %+v, want %+v", distinct, want)
	}
}

// TestRecipientRouteJSON: the route is a new optional field of recipients_json. A
// recipient without one marshals exactly as before, and a reader that does not know the
// field (an older node) decodes the rest unchanged.
func TestRecipientRouteJSON(t *testing.T) {
	plain, err := json.Marshal(Recipient{AddressType: "from", EmailAddress: "user@domain", Name: "N"})
	if err != nil || string(plain) != `{"email":"user@domain","type":"from","name":"N"}` {
		t.Errorf("recipient without a route = %s, %v", plain, err)
	}
	routed, err := json.Marshal(Recipient{AddressType: "from", EmailAddress: "user@domain", Route: "@route"})
	if err != nil || string(routed) != `{"email":"user@domain","type":"from","route":"@route"}` {
		t.Errorf("routed recipient = %s, %v", routed, err)
	}
	var old struct {
		EmailAddress string `json:"email"`
		AddressType  string `json:"type"`
		Name         string `json:"name,omitempty"`
		Group        string `json:"group,omitempty"`
		GroupEnd     bool   `json:"group_end,omitempty"`
	}
	if err := json.Unmarshal(routed, &old); err != nil || old.EmailAddress != "user@domain" || old.AddressType != "from" {
		t.Errorf("a reader without the field decoded %+v, %v", old, err)
	}
}
