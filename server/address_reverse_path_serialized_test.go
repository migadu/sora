package server

import "testing"

// NewSerializedReversePath reads a mailbox in its written form (the Admin API "from")
// and decodes it once. Each case names the same mailbox go-smtp would hand
// NewReversePath for that MAIL FROM, and both must return the same address.
func TestNewSerializedReversePath(t *testing.T) {
	for _, tc := range []struct{ in, decoded, want string }{
		{`First..Last@Example.com`, `First..Last@Example.com`, `First..Last@example.com`},
		{`a@b.example@example.com`, `a@b.example@example.com`, `"a@b.example"@example.com`},
		{`"John Doe"@example.com`, `John Doe@example.com`, `"John Doe"@example.com`},
		{`"John.Doe"@example.com`, `John.Doe@example.com`, `John.Doe@example.com`},
		{`"J\ohn"@example.com`, `John@example.com`, `John@example.com`},
		{`"a@b.example"@example.com`, `a@b.example@example.com`, `"a@b.example"@example.com`},
		{`"Say \"Hi\""@example.com`, `Say "Hi"@example.com`, `"Say \"Hi\""@example.com`},
		{`"Back\\Slash"@example.com`, `Back\Slash@example.com`, `"Back\\Slash"@example.com`},
		{`" sender "@example.com`, ` sender @example.com`, `" sender "@example.com`},
		{`"\"Sender\""@example.com`, `"Sender"@example.com`, `"\"Sender\""@example.com`},
		{`"José"@Example.com`, `José@Example.com`, `José@example.com`},
		{`José+Tag@example.com`, `José+Tag@example.com`, `José+Tag@example.com`},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := NewSerializedReversePath(tc.in)
			if err != nil {
				t.Fatalf("NewSerializedReversePath(%q): %v", tc.in, err)
			}
			decoded, err := NewReversePath(tc.decoded)
			if err != nil {
				t.Fatalf("NewReversePath(%q): %v", tc.decoded, err)
			}
			if got != decoded || got.FullAddress() != tc.want {
				t.Errorf("NewSerializedReversePath(%q) = %q, NewReversePath(%q) = %q, want both %q",
					tc.in, got.FullAddress(), tc.decoded, decoded.FullAddress(), tc.want)
			}
		})
	}
}

// A written mailbox that is not RFC 5321 §4.1.2 syntax is refused rather than read as
// some other mailbox: a `"` or space outside one whole quoted string, a quoted string
// that does not end, and invalid UTF-8, also where a "\" sits between its bytes.
func TestNewSerializedReversePathRefuses(t *testing.T) {
	for _, in := range []string{
		``, `<>`, `<sender@example.com>`, `not an address`, `sender@bad_domain.example`,
		`John Doe@example.com`,
		`Sen"der@example.com`,
		`Sender"@example.com`,
		`a@b"c@example.com`,
		`Back\Slash@example.com`,
		`"Sender@example.com`,
		`"Sender\"@example.com`,
		`"Sen"der"@example.com`,
		`"a"@b@example.com`,
		`"a"b@example.com`,
		`""@example.com`,
		"\"\xc3\\\xa9\"@example.com",
		"\xc3@example.com",
		"\"\\\xc3\xa9\"@example.com",
		"\"A\rB\"@example.com",
		"\"A\\\rB\"@example.com",
		`a@@example.com`,
		`@example.com`,
	} {
		if addr, err := NewSerializedReversePath(in); err == nil {
			t.Errorf("NewSerializedReversePath(%q) = %q, want an error", in, addr.FullAddress())
		}
	}
}
