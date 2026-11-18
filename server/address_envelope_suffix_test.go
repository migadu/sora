package server

import "testing"

// The master-token suffix (user@domain@SUFFIX) belongs to login names, not to envelope
// addresses (#1938). go-smtp hands a quoted local part over unquoted, so the sender
// `"a@b.example"@example.com` arrives as "a@b.example@example.com": it is one quoted
// local part and a domain, never the address a@b.example with the suffix "example.com".
func TestNewReversePathNoMasterSuffix(t *testing.T) {
	for _, tt := range []struct {
		in, full, local, domain string
	}{
		// `"a@b"@example.com`
		{"a@b@example.com", `"a@b"@example.com`, `"a@b"`, "example.com"},
		// `"a@b.example"@example.com`
		{"a@b.example@example.com", `"a@b.example"@example.com`, `"a@b.example"`, "example.com"},
		// `"User+Tag@Example.org"@Example.com`: a quoted local part has no detail.
		{"User+Tag@Example.org@Example.com", `"user+tag@example.org"@example.com`, `"user+tag@example.org"`, "example.com"},
		// `"user@example.com"@SUFFIX`: the last "@" starts the domain.
		{"user@example.com@SUFFIX", `"user@example.com"@suffix`, `"user@example.com"`, "suffix"},
	} {
		addr, err := NewReversePath(tt.in)
		if err != nil {
			t.Errorf("NewReversePath(%q): %v", tt.in, err)
			continue
		}
		if addr.HasSuffix() {
			t.Errorf("NewReversePath(%q) has master suffix %q", tt.in, addr.Suffix())
		}
		if addr.FullAddress() != tt.full || addr.LocalPart() != tt.local || addr.Domain() != tt.domain || addr.Detail() != "" {
			t.Errorf("NewReversePath(%q) = full %q local %q domain %q detail %q, want %q %q %q \"\"",
				tt.in, addr.FullAddress(), addr.LocalPart(), addr.Domain(), addr.Detail(), tt.full, tt.local, tt.domain)
		}
	}

	// Login names keep the master-token parse.
	addr, err := NewAddress("user@example.com@SUFFIX")
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	if addr.Suffix() != "SUFFIX" || addr.BaseAddress() != "user@example.com" {
		t.Errorf("NewAddress(user@example.com@SUFFIX) = base %q suffix %q, want user@example.com SUFFIX", addr.BaseAddress(), addr.Suffix())
	}
}
