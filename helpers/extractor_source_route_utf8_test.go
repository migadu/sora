package helpers

import (
	"slices"
	"testing"

	"github.com/emersion/go-message/mail"
)

// RFC 6532 §3.2 extends atext, dtext and quoted-pair's VCHAR with UTF8-non-ascii, so a
// route hop may be an internationalized domain. These are the cases go-imap's
// ExtractEnvelope accepts for an attached message (TestExtractEnvelopeUTF8SourceRoute
// there); the message's own ENVELOPE must report the same addresses and routes (#2124).
func TestExtractRecipientsUTF8SourceRoutes(t *testing.T) {
	routed := func(route string) Recipient {
		return Recipient{AddressType: "to", EmailAddress: "user@domain", Route: route}
	}
	plain := Recipient{AddressType: "to", EmailAddress: "plain@domain"}
	for _, tc := range []struct {
		name, value string
		want        []Recipient
	}{
		{"single hop", "<@routé.example:user@domain>", []Recipient{routed("@routé.example")}},
		{"issue example", "<@bücher.example:user@domain>", []Recipient{routed("@bücher.example")}},
		{"mixed list", "plain@domain, <@routé.example:user@domain>, <@ascii:other@domain>", []Recipient{
			plain, routed("@routé.example"), {AddressType: "to", EmailAddress: "other@domain", Route: "@ascii"},
		}},
		{"group", "team: <@routé.example:user@domain>, plain@domain;, after@domain", []Recipient{
			{AddressType: "to", Group: "team"}, routed("@routé.example"), plain, {AddressType: "to", GroupEnd: true},
			{AddressType: "to", EmailAddress: "after@domain"},
		}},
		{"multiple hops", "<@routé.example, @例え.example:user@domain>", []Recipient{routed("@routé.example,@例え.example")}},
		{"non-BMP", "<@𐐀.example:user@domain>", []Recipient{routed("@𐐀.example")}},
		{"replacement character", "<@�.example:user@domain>", []Recipient{routed("@�.example")}},
		{"domain literal", "<@[例え:route]:user@domain>", []Recipient{routed("@[例え:route]")}},
		{"quoted pair in literal", "<@[route\\é]:user@domain>", []Recipient{routed("@[route\\é]")}},
		{"comments", "<(前) @route (café):user@domain>", []Recipient{routed("@route")}},
		{"quoted pair in comment", "<@route (caf\\é):user@domain>", []Recipient{routed("@route")}},
		// net/mail takes a UTF-8 domain in the remaining addr-spec as it is.
		{"UTF-8 domain in the address too", "<@bücher.example:user@bücher.example>",
			[]Recipient{{AddressType: "to", EmailAddress: "user@bücher.example", Route: "@bücher.example"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := mail.HeaderFromMap(map[string][]string{"To": {tc.value}})
			if got := ExtractRecipients(h.Header); !slices.Equal(got, tc.want) {
				t.Errorf("ExtractRecipients(%q)\n got %+v\nwant %+v", tc.value, got, tc.want)
			}
			if _, err := ParseAddressList(tc.value); err != nil {
				t.Errorf("ParseAddressList(%q): %v", tc.value, err)
			}
		})
	}
}

// Invalid UTF-8 in a route, in a hop, a comment or after a backslash, is not a route, so
// the value is not an address list (go-imap's TestExtractEnvelopeMalformedUTF8SourceRoute).
// ExtractRecipients removes invalid bytes from a header before it parses it, as it does
// for every address header, so there the bytes are gone before the route is read.
func TestMalformedUTF8SourceRouteIsNotAnAddress(t *testing.T) {
	for _, encoding := range []struct{ name, bytes string }{
		{"isolated continuation", "\x80"},
		{"truncated", "\xe2\x82"},
		{"overlong", "\xc0\xaf"},
		{"surrogate", "\xed\xa0\x80"},
		{"out of range", "\xf4\x90\x80\x80"},
	} {
		for _, context := range []struct{ name, before, after string }{
			{"atom", "<@route", ".example:user@domain>"},
			{"literal", "<@[route", "]:user@domain>"},
			{"leading comment", "<(route", ") @route:user@domain>"},
			{"comment", "<@route (route", "):user@domain>"},
			{"quoted pair in literal", "<@[route\\", "]:user@domain>"},
			{"quoted pair in comment", "<@route (route\\", "):user@domain>"},
		} {
			t.Run(encoding.name+"/"+context.name, func(t *testing.T) {
				value := context.before + encoding.bytes + context.after
				if got, err := ParseAddressList(value); err == nil {
					t.Errorf("ParseAddressList(%q) = %+v, want an error", value, got)
				}
			})
		}
	}
	// A stored header is read without its invalid bytes, in a route as anywhere else,
	// and its addresses are kept, as before.
	for _, tc := range []struct {
		value string
		want  []Recipient
	}{
		{"Na\x80me <@route:user@domain>, pl\xffain@domain", []Recipient{
			{AddressType: "to", Name: "Name", EmailAddress: "user@domain", Route: "@route"}, {AddressType: "to", EmailAddress: "plain@domain"}}},
		{"<@route\x80.example:user@domain>", []Recipient{{AddressType: "to", EmailAddress: "user@domain", Route: "@route.example"}}},
		{"<(route\xff) @route:user@domain>", []Recipient{{AddressType: "to", EmailAddress: "user@domain", Route: "@route"}}},
		{"caf\xe9@example.com", []Recipient{{AddressType: "to", EmailAddress: "caf@example.com"}}},
		{"Na\x00me <us\x00er@example.com>", []Recipient{{AddressType: "to", Name: "Name", EmailAddress: "user@example.com"}}},
		{"te\xc0am: a@example.com;", []Recipient{{AddressType: "to", Group: "team"}, {AddressType: "to", EmailAddress: "a@example.com"}, {AddressType: "to", GroupEnd: true}}},
	} {
		h := mail.HeaderFromMap(map[string][]string{"To": {tc.value}})
		if got := ExtractRecipients(h.Header); !slices.Equal(got, tc.want) {
			t.Errorf("ExtractRecipients(%q) = %+v, want %+v", tc.value, got, tc.want)
		}
	}
}
