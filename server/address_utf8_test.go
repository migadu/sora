package server

import (
	"strings"
	"testing"
)

// RFC 6531 §3.3 extends <atext> with UTF8-non-ascii (RFC 6532 §3.1): any valid non-ASCII
// UTF-8 may appear in a dot-string local part, while the ASCII graphics and controls that
// RFC 5321 excludes stay excluded. A U-label domain is folded to its A-label (RFC 6531 §3.2),
// so the stored credential address and the DNS name are what the rest of the server sees.
func TestNewAddressSMTPUTF8(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		wantFullAddress string
		wantLocalPart   string
		wantDomain      string
		wantDetail      string
		wantBaseAddress string
		wantSuffix      string
		wantErr         string // substring of the error; "" means the address must parse
	}{
		{
			name:            "non-ascii detail (the prod bounce)",
			input:           "me+josé@dejanstrbac.com",
			wantFullAddress: "me+josé@dejanstrbac.com",
			wantLocalPart:   "me+josé",
			wantDomain:      "dejanstrbac.com",
			wantDetail:      "josé",
			wantBaseAddress: "me@dejanstrbac.com",
		},
		{
			name:            "non-ascii base local part",
			input:           "josé@example.com",
			wantFullAddress: "josé@example.com",
			wantLocalPart:   "josé",
			wantDomain:      "example.com",
			wantBaseAddress: "josé@example.com",
		},
		{
			name:            "non-ascii upper case is lowercased like ascii",
			input:           "JOSÉ@Example.COM",
			wantFullAddress: "josé@example.com",
			wantLocalPart:   "josé",
			wantDomain:      "example.com",
			wantBaseAddress: "josé@example.com",
		},
		{
			name:            "three-byte sequences (CJK)",
			input:           "用户@example.com",
			wantFullAddress: "用户@example.com",
			wantLocalPart:   "用户",
			wantDomain:      "example.com",
			wantBaseAddress: "用户@example.com",
		},
		{
			name:            "four-byte sequence",
			input:           "😀@example.com",
			wantFullAddress: "😀@example.com",
			wantLocalPart:   "😀",
			wantDomain:      "example.com",
			wantBaseAddress: "😀@example.com",
		},
		{
			name:            "dot-string of non-ascii atoms",
			input:           "jo.sé@example.com",
			wantFullAddress: "jo.sé@example.com",
			wantLocalPart:   "jo.sé",
			wantDomain:      "example.com",
			wantBaseAddress: "jo.sé@example.com",
		},
		{
			name:            "master token suffix survives a non-ascii user",
			input:           "josé+tag@example.com@MasterToken",
			wantFullAddress: "josé+tag@example.com@MasterToken",
			wantLocalPart:   "josé+tag",
			wantDomain:      "example.com",
			wantDetail:      "tag",
			wantBaseAddress: "josé@example.com",
			wantSuffix:      "MasterToken",
		},
		{
			name:            "u-label domain is folded to its a-label",
			input:           "user@bücher.example",
			wantFullAddress: "user@xn--bcher-kva.example",
			wantLocalPart:   "user",
			wantDomain:      "xn--bcher-kva.example",
			wantBaseAddress: "user@xn--bcher-kva.example",
		},
		{
			name:    "malformed utf-8 in the local part",
			input:   "jos\xe9@example.com",
			wantErr: "not valid UTF-8",
		},
		{
			name:    "malformed utf-8 in the domain",
			input:   "user@ex\xffample.com",
			wantErr: "not valid UTF-8",
		},
		{
			name:    "ascii specials are still excluded",
			input:   "foo:bar@example.com",
			wantErr: "unacceptable local part",
		},
		{
			name:    "quoted local part is still not a dot-string",
			input:   `"josé"@example.com`,
			wantErr: "unacceptable local part",
		},
		{
			name:    "leading dot is still a bad dot-string",
			input:   ".josé@example.com",
			wantErr: "unacceptable local part",
		},
		{
			name:    "consecutive dots are still a bad dot-string",
			input:   "jo..sé@example.com",
			wantErr: "unacceptable local part",
		},
		{
			name:    "u-label with a character IDNA does not allow",
			input:   "user@bü_cher.example",
			wantErr: "unacceptable domain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAddress(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("NewAddress(%q) = %+v, want error containing %q", tt.input, got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NewAddress(%q) error = %q, want it to contain %q", tt.input, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewAddress(%q) unexpected error: %v", tt.input, err)
			}
			if got.FullAddress() != tt.wantFullAddress {
				t.Errorf("FullAddress() = %q, want %q", got.FullAddress(), tt.wantFullAddress)
			}
			if got.LocalPart() != tt.wantLocalPart {
				t.Errorf("LocalPart() = %q, want %q", got.LocalPart(), tt.wantLocalPart)
			}
			if got.Domain() != tt.wantDomain {
				t.Errorf("Domain() = %q, want %q", got.Domain(), tt.wantDomain)
			}
			if got.Detail() != tt.wantDetail {
				t.Errorf("Detail() = %q, want %q", got.Detail(), tt.wantDetail)
			}
			if got.BaseAddress() != tt.wantBaseAddress {
				t.Errorf("BaseAddress() = %q, want %q", got.BaseAddress(), tt.wantBaseAddress)
			}
			if got.Suffix() != tt.wantSuffix {
				t.Errorf("Suffix() = %q, want %q", got.Suffix(), tt.wantSuffix)
			}
		})
	}
}

// The RFC 5321 length limits are octet limits and RFC 6531 keeps them as such, so a
// multibyte local part is bounded by its encoded length, not by its rune count.
func TestNewAddressSMTPUTF8LengthIsInOctets(t *testing.T) {
	atLimit := strings.Repeat("é", MaxLocalPartLength/2) // 2 octets each: exactly the limit
	if _, err := NewAddress(atLimit + "@example.com"); err != nil {
		t.Fatalf("a %d-octet local part must be accepted: %v", len(atLimit), err)
	}
	overLimit := strings.Repeat("é", MaxLocalPartLength/2+1)
	if _, err := NewAddress(overLimit + "@example.com"); err == nil {
		t.Fatalf("a %d-octet local part must be rejected", len(overLimit))
	}
}

func TestIsASCII(t *testing.T) {
	for _, s := range []string{"", "user@example.com", "me+tag@example.com", "a\tb"} {
		if !IsASCII(s) {
			t.Errorf("IsASCII(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"josé@example.com", "用户", "\xe9", "user@bücher.example"} {
		if IsASCII(s) {
			t.Errorf("IsASCII(%q) = true, want false", s)
		}
	}
}
