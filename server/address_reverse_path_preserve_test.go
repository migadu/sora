package server

import "testing"

// NewReversePath keeps the sender's local part as the sender wrote it (#2101). The
// reverse-path is where vacation replies and the MAIL FROM of relayed redirects go, and
// "The local-part of a mailbox MUST BE treated as case sensitive. Therefore, SMTP
// implementations MUST take care to preserve the case of mailbox local-parts" (RFC 5321
// §2.4). Its input is the mailbox as go-smtp hands it over, with a quoted local part
// already decoded: it is quoted again only when it needs quotes, with "the minimum
// quoting possible" (RFC 5321 §4.1.2). The domain is not case sensitive and is
// lower-cased.
func TestNewReversePathPreservesLocalPart(t *testing.T) {
	for _, tt := range []struct {
		name, in, full, local, detail string
	}{
		{"quoted, as go-smtp hands it over", `John Doe@example.com`, `"John Doe"@example.com`, `"John Doe"`, ""},
		{"go-smtp unquoted dot-string", `John.Doe@Example.COM`, `John.Doe@example.com`, `John.Doe`, ""},
		{"detail keeps its case", `John+Tag@example.com`, `John+Tag@example.com`, `John+Tag`, "Tag"},
		{"lenient dot-string keeps its case", `First..Last@example.com`, `First..Last@example.com`, `First..Last`, ""},
		{"quoted pairs, go-smtp form", `Say "Hi"@example.com`, `"Say \"Hi\""@example.com`, `"Say \"Hi\""`, ""},
		{"decoded backslash", `Back\Slash@example.com`, `"Back\\Slash"@example.com`, `"Back\\Slash"`, ""},
		{"quoted at sign, go-smtp form", `A@B.example@example.com`, `"A@B.example"@example.com`, `"A@B.example"`, ""},
		{"non-ASCII local part", `José@Example.com`, `José@example.com`, `José`, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := NewReversePath(tt.in)
			if err != nil {
				t.Fatalf("NewReversePath(%q): %v", tt.in, err)
			}
			if addr.FullAddress() != tt.full || addr.LocalPart() != tt.local || addr.Domain() != "example.com" || addr.Detail() != tt.detail {
				t.Errorf("NewReversePath(%q) = full %q local %q domain %q detail %q, want %q %q %q %q",
					tt.in, addr.FullAddress(), addr.LocalPart(), addr.Domain(), addr.Detail(), tt.full, tt.local, "example.com", tt.detail)
			}
		})
	}
}

// go-smtp has already decoded the quoted string on the wire. Quote characters left in
// the decoded local part are the mailbox's own (MAIL FROM:<"\"Sender\""@example.com>
// hands over `"Sender"@example.com`); decoding them again would name another mailbox,
// so they are kept and escaped once.
func TestNewReversePathPreservesDecodedQuotes(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`"Sender"@example.com`, `"\"Sender\""@example.com`},
		{`"John Doe"@example.com`, `"\"John Doe\""@example.com`},
		{`"A@B"@example.com`, `"\"A@B\""@example.com`},
		{`"J\ohn"@example.com`, `"\"J\\ohn\""@example.com`},
		{`Sen"der@example.com`, `"Sen\"der"@example.com`},
		{`Sender"@example.com`, `"Sender\""@example.com`},
	} {
		addr, err := NewReversePath(tc.in)
		if err != nil {
			t.Fatalf("NewReversePath(%q): %v", tc.in, err)
		}
		if addr.FullAddress() != tc.want {
			t.Errorf("NewReversePath(%q) = %q, want %q", tc.in, addr.FullAddress(), tc.want)
		}
	}
}
