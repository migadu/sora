package server

import "testing"

// NewReversePath keeps the sender's local part as the sender wrote it (#2101). The
// reverse-path is where vacation replies and the MAIL FROM of relayed redirects go, and
// "The local-part of a mailbox MUST BE treated as case sensitive. Therefore, SMTP
// implementations MUST take care to preserve the case of mailbox local-parts" (RFC 5321
// §2.4). A quoted local part comes in two forms: go-smtp hands it over unquoted, the
// Admin API passes it as written. Both are the same mailbox ("all quoted forms MUST be
// treated as equivalent", RFC 5321 §4.1.2) and come back once, with "the minimum quoting
// possible". The domain is not case sensitive and is lower-cased.
func TestNewReversePathPreservesLocalPart(t *testing.T) {
	for _, tt := range []struct {
		name, in, full, local, detail string
	}{
		{"quoted, as the Admin API passes it", `"John Doe"@example.com`, `"John Doe"@example.com`, `"John Doe"`, ""},
		{"quoted, as go-smtp hands it over", `John Doe@example.com`, `"John Doe"@example.com`, `"John Doe"`, ""},
		{"quoted dot-string needs no quotes", `"John.Doe"@example.com`, `John.Doe@example.com`, `John.Doe`, ""},
		{"go-smtp unquoted dot-string", `John.Doe@Example.COM`, `John.Doe@example.com`, `John.Doe`, ""},
		{"detail keeps its case", `John+Tag@example.com`, `John+Tag@example.com`, `John+Tag`, "Tag"},
		{"lenient dot-string keeps its case", `First..Last@example.com`, `First..Last@example.com`, `First..Last`, ""},
		{"quoted lenient dot-string", `"First..Last"@example.com`, `First..Last@example.com`, `First..Last`, ""},
		{"quoted pairs, quoted form", `"Say \"Hi\""@example.com`, `"Say \"Hi\""@example.com`, `"Say \"Hi\""`, ""},
		{"quoted pairs, go-smtp form", `Say "Hi"@example.com`, `"Say \"Hi\""@example.com`, `"Say \"Hi\""`, ""},
		{"quoted backslash, quoted form", `"Back\\Slash"@example.com`, `"Back\\Slash"@example.com`, `"Back\\Slash"`, ""},
		{"needless quoted pair", `"J\ohn"@example.com`, `John@example.com`, `John`, ""},
		{"quoted at sign, quoted form", `"A@B.example"@example.com`, `"A@B.example"@example.com`, `"A@B.example"`, ""},
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
