package server

import (
	"errors"
	"strings"
	"testing"
)

// NewReversePath reads a MAIL FROM mailbox as go-smtp hands it over (a quoted local
// part already unquoted) as leniently as go-smtp parses it, and returns it in a form
// that is safe to write into MAIL FROM, RCPT TO or a To: field (#1907).
func TestNewReversePathLenient(t *testing.T) {
	for _, tt := range []struct {
		in, full, local, domain, detail string
	}{
		// go-smtp's dot-string: leading, trailing and consecutive dots.
		{"first..last@example.com", "first..last@example.com", "first..last", "example.com", ""},
		{".lead@example.com", ".lead@example.com", ".lead", "example.com", ""},
		{"trail.@example.com", "trail.@example.com", "trail.", "example.com", ""},
		{"Trail..+Tag@Example.COM", "trail..+tag@example.com", "trail..+tag", "example.com", "tag"},
		// A dotless domain and address literals.
		{"user@localhost", "user@localhost", "user", "localhost", ""},
		{"user@[192.0.2.1]", "user@[192.0.2.1]", "user", "[192.0.2.1]", ""},
		{"user@[IPv6:2001:db8::1]", "user@[ipv6:2001:db8::1]", "user", "[ipv6:2001:db8::1]", ""},
		// A quoted local part arrives unquoted and is quoted again, "\" and `"` escaped.
		{"quoted local@example.com", `"quoted local"@example.com`, `"quoted local"`, "example.com", ""},
		{`say "hi"@example.com`, `"say \"hi\""@example.com`, `"say \"hi\""`, "example.com", ""},
		{`back\slash@example.com`, `"back\\slash"@example.com`, `"back\\slash"`, "example.com", ""},
		{"a b@c@example.com", `"a b@c"@example.com`, `"a b@c"`, "example.com", ""},
		{" lead space@example.com", `" lead space"@example.com`, `" lead space"`, "example.com", ""},
		{"a+b c@example.com", `"a+b c"@example.com`, `"a+b c"`, "example.com", ""},
		// RFC 6531: non-ASCII local parts and a U-label domain, as in NewAddress.
		{"jo..sé@localhost", "jo..sé@localhost", "jo..sé", "localhost", ""},
		{"user.@bücher", "user.@xn--bcher-kva", "user.", "xn--bcher-kva", ""},
	} {
		addr, err := NewReversePath(tt.in)
		if err != nil {
			t.Errorf("NewReversePath(%q): %v", tt.in, err)
			continue
		}
		if addr.FullAddress() != tt.full || addr.LocalPart() != tt.local || addr.Domain() != tt.domain || addr.Detail() != tt.detail {
			t.Errorf("NewReversePath(%q) = full %q local %q domain %q detail %q, want %q %q %q %q",
				tt.in, addr.FullAddress(), addr.LocalPart(), addr.Domain(), addr.Detail(), tt.full, tt.local, tt.domain, tt.detail)
		}
		if addr.HasSuffix() {
			t.Errorf("NewReversePath(%q) has suffix %q", tt.in, addr.Suffix())
		}
		// Forward-paths stay strict.
		if _, err := NewAddress(tt.in); err == nil {
			t.Errorf("NewAddress(%q) accepted a sender only the reverse-path takes", tt.in)
		}
	}
}

// Every sender NewAddress accepts comes back from NewReversePath exactly as from
// NewAddress, so nothing changes for the senders accepted before #1907. A sender with
// a master-token suffix is not one of them (TestNewReversePathNoMasterSuffix, #1938).
func TestNewReversePathMatchesNewAddress(t *testing.T) {
	for _, in := range []string{
		"user@example.com",
		"User+Tag@Example.com",
		"a/b=c@example.com",
		"josé@bücher.example",
	} {
		want, err := NewAddress(in)
		if err != nil {
			t.Fatalf("NewAddress(%q): %v", in, err)
		}
		got, err := NewReversePath(in)
		if err != nil {
			t.Fatalf("NewReversePath(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("NewReversePath(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestNewReversePathRefused(t *testing.T) {
	for _, in := range []string{
		"",
		"user",
		"@example.com",
		"user@",
		"user@example..com",
		"user@.example.com",
		"user@example.com.",
		"user@-",
		"user@-example.com",
		"user@exa mple.com",
		`user@exa"mple.com`,
		"user@exa<mple.com",
		"user@[192.0.2.1",
		"user@[1[2]",
		"user@[]",
		// No control character survives: a CR or LF would end a relayed command or
		// header line.
		"us\rer@example.com",
		"us\ner@example.com",
		"quoted\r\nRCPT TO:<x@example.org>@example.com",
		"user@example.com\r\n",
		"us\x00er@example.com",
		"us\ter@example.com",
		"us\x7fer@example.com",
		"us\xffer@example.com",
		// Length limits, measured on the form returned (quotes and escapes included).
		strings.Repeat("a", MaxLocalPartLength-1) + "..@example.com",
		"a b" + strings.Repeat("c", MaxLocalPartLength-4) + "@example.com",
		strings.Repeat(`"`, MaxLocalPartLength/2) + "@example.com",
		"user@" + strings.Repeat("a.", 128) + "com",
	} {
		if addr, err := NewReversePath(in); err == nil {
			t.Errorf("NewReversePath(%q) = %q, want an error", in, addr.FullAddress())
		} else if !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("NewReversePath(%q): %v does not match ErrInvalidAddress", in, err)
		}
	}
}
