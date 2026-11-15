package server

import (
	"errors"
	"strings"
	"testing"
)

// TestNewAddressErrorsMatchErrInvalidAddress pins down that every NewAddress failure
// is an ErrInvalidAddress, so a caller several layers up (the Admin API, the database
// circuit breaker) tells a malformed address from a failure without matching text.
func TestNewAddressErrorsMatchErrInvalidAddress(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"malformed utf-8", "jos\xe9@example.com"},
		{"whitespace", "us er@example.com"},
		{"empty", "   "},
		{"missing @", "not-an-address"},
		{"local part too long", strings.Repeat("a", MaxLocalPartLength+1) + "@example.com"},
		{"unacceptable local part", "foo:bar@example.com"},
		{"u-label IDNA refuses", "user@bü_cher.example"},
		{"domain too long", "user@" + strings.Repeat("a", MaxDomainLength+1)},
		{"unacceptable domain", "user@-example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAddress(tt.input)
			if err == nil {
				t.Fatalf("NewAddress(%q) succeeded, want an error", tt.input)
			}
			if !errors.Is(err, ErrInvalidAddress) {
				t.Errorf("NewAddress(%q) error %q does not match ErrInvalidAddress", tt.input, err)
			}
		})
	}

	// The text stays the reason alone: callers already prefix their own context
	// ("invalid email address: ...").
	_, err := NewAddress("not-an-address")
	if want := "address missing @: 'not-an-address'"; err == nil || err.Error() != want {
		t.Errorf("NewAddress error text = %v, want %q", err, want)
	}
}
