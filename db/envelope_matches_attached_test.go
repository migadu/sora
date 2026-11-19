package db

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/emersion/go-message/mail"
	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/helpers"
)

// TestTopLevelEnvelopeMatchesAttached: a message's own ENVELOPE is built from the
// recipients Sora stores (helpers.ExtractRecipients, BuildEnvelope); its ENVELOPE as a
// message/rfc822 attachment is built by go-imap (imapserver.ExtractEnvelope). Both are
// the same parse of the same headers, so every address list must come out equal: the
// same addresses, routes, display names and group records, in the same order (#2124),
// also for a header with bytes that are not text.
func TestTopLevelEnvelopeMatchesAttached(t *testing.T) {
	for _, value := range []string{
		// plain lists and display names
		"a@example.com", "A <a@example.com>, b@example.com (B)", "=?utf-8?q?Caf=C3=A9?= <a@example.com>",
		`"a@b"@example.com`, "a@example.com, A <a@example.com>", "user@bücher.example",
		// groups
		"group: g1@d1.org, g2@d2.org;, group2: g3@d3.org;", "group:;, group2: (foo) ;", "undisclosed-recipients:;",
		"Plain <plain@example.com>, team: a@example.com, B <b@example.com>;, last@example.com",
		`"Team: A" (x) :a@example.com;, =?utf-8?q?Caf=C3=A9?= list:;`, "team: a@[2001:db8::1];",
		// group names
		`"=?utf-8?q?literal?=": a@example.com;`, `"=?utf-8?q?literal?=" =?utf-8?q?real?= : a@example.com;`,
		`"A""B": a@example.com;`, `A"B": a@example.com;`, `"two  words": a@example.com;`, " Team : a@example.com;",
		"a@b: x@example.com;", `"b@z": x@example.com;`, `"""":;`,
		// malformed groups
		"g: a@example.com", "g: h: a@example.com;;", "a@example.com; b@example.com", ": a@example.com;",
		// comments and white space in an addr-spec
		"<user-from (comment)@ (comment) domain.org>", "Real Name <user (c) @ example.com>", "team: inside (comment)@ (comment) example.com;",
		`"x (y) @z" (c) @ example.com`,
		// source routes
		"<@route:user@domain>", "Real Name < (before) @first (hop) , (between) @second : user (local) @ domain >",
		"plain@domain,, <@first:one@domain>, Two <two@domain>, <@second,@third:three@domain>",
		"<@a:before@domain>, team: one@domain, <@b:two@domain>;, <@c:after@domain>", "<@first..example:user@domain>",
		// internationalized route hops
		"<@bücher.example:user@domain>", "<@routé.example, @例え.example:user@domain>", "<@[例え:route]:user@domain>",
		"team: <@routé.example:user@domain>, plain@domain;, after@domain", "<@bücher.example:user@bücher.example>",
		// bytes that are not text: invalid UTF-8 and NUL are removed before parsing, on
		// both sides by the same function (mailaddr.ParseListLenient)
		"caf\xe9@example.com", "Na\x80me <user@example.com>, pl\xffain@example.com", "Na\x00me <us\x00er@example.com>",
		"J\xc3 <j@example.com>", "te\xc0am: a@example.com;", "\x96: a@example.com;", "te\x00am:;",
		"<@route\x80.example:user@domain>", "<(route\xff) @route:user@domain>", "<@[route\xe2\x82]:user@domain>",
		"<@route (route\\\x80):user@domain>", "=?utf-8?q?ab=80c?= <a@example.com>", "=?utf-8?q?te=00am?=: a@example.com;",
		"\uFFFD <j@example.com>", "\xff", "\x00",
	} {
		t.Run(value, func(t *testing.T) {
			h := mail.HeaderFromMap(map[string][]string{"From": {value}, "To": {value}, "Cc": {value}, "Bcc": {value}})
			raw, err := json.Marshal(helpers.ExtractRecipients(h.Header))
			if err != nil {
				t.Fatal(err)
			}
			top, err := BuildEnvelope(&Message{RecipientsJSON: raw})
			if err != nil {
				t.Fatal(err)
			}
			attached := imapserver.ExtractEnvelope(h.Header.Header)
			for _, f := range []struct {
				name          string
				top, attached []imap.Address
			}{
				{"From", top.From, attached.From}, {"To", top.To, attached.To},
				{"Cc", top.Cc, attached.Cc}, {"Bcc", top.Bcc, attached.Bcc},
			} {
				if !slices.Equal(f.top, f.attached) {
					t.Errorf("%s: %s\n top-level %+v\n attached  %+v", f.name, value, f.top, f.attached)
				}
			}
		})
	}
}
