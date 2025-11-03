package server

import (
	"testing"
)

func TestParseAddressWithProxySeparator(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectError  bool
		expectAddr   string
		expectDomain string
		expectLocal  string
		expectDetail string
		expectSuffix string
		expectBase   string
	}{
		{
			name:         "simple email without suffix",
			input:        "user@example.com",
			expectError:  false,
			expectAddr:   "user@example.com",
			expectDomain: "example.com",
			expectLocal:  "user",
			expectDetail: "",
			expectSuffix: "",
			expectBase:   "user@example.com",
		},
		{
			name:         "email with * suffix",
			input:        "user@example.com*admin",
			expectError:  false,
			expectAddr:   "user@example.com*admin",
			expectDomain: "example.com",
			expectLocal:  "user",
			expectDetail: "",
			expectSuffix: "admin",
			expectBase:   "user@example.com",
		},
		{
			name:         "email with +detail and * suffix",
			input:        "user+tag@example.com*admin",
			expectError:  false,
			expectAddr:   "user+tag@example.com*admin",
			expectDomain: "example.com",
			expectLocal:  "user+tag",
			expectDetail: "tag",
			expectSuffix: "admin",
			expectBase:   "user@example.com",
		},
		{
			name:         "suffix with * character (password)",
			input:        "user@example.com*pass*word",
			expectError:  false,
			expectAddr:   "user@example.com*pass*word",
			expectDomain: "example.com",
			expectLocal:  "user",
			expectDetail: "",
			expectSuffix: "pass*word", // Suffix can contain * characters
			expectBase:   "user@example.com",
		},
		{
			name:         "suffix with @ character",
			input:        "user@example.com*admin@proxy",
			expectError:  false,
			expectAddr:   "user@example.com*admin@proxy",
			expectDomain: "example.com",
			expectLocal:  "user",
			expectDetail: "",
			expectSuffix: "admin@proxy", // Suffix can contain @ characters
			expectBase:   "user@example.com",
		},
		{
			name:         "uppercase normalized",
			input:        "User@Example.COM*ADMIN",
			expectError:  false,
			expectAddr:   "user@example.com*admin",
			expectDomain: "example.com",
			expectLocal:  "user",
			expectDetail: "",
			expectSuffix: "admin",
			expectBase:   "user@example.com",
		},
		{
			name:        "invalid - empty",
			input:       "",
			expectError: true,
		},
		{
			name:        "invalid - no @",
			input:       "userexample.com",
			expectError: true,
		},
		{
			name:        "invalid - whitespace",
			input:       "user @example.com",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := NewAddress(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if addr.FullAddress() != tt.expectAddr {
				t.Errorf("FullAddress: expected '%s', got '%s'", tt.expectAddr, addr.FullAddress())
			}
			if addr.Domain() != tt.expectDomain {
				t.Errorf("Domain: expected '%s', got '%s'", tt.expectDomain, addr.Domain())
			}
			if addr.LocalPart() != tt.expectLocal {
				t.Errorf("LocalPart: expected '%s', got '%s'", tt.expectLocal, addr.LocalPart())
			}
			if addr.Detail() != tt.expectDetail {
				t.Errorf("Detail: expected '%s', got '%s'", tt.expectDetail, addr.Detail())
			}
			if addr.Suffix() != tt.expectSuffix {
				t.Errorf("Suffix: expected '%s', got '%s'", tt.expectSuffix, addr.Suffix())
			}
			if addr.BaseAddress() != tt.expectBase {
				t.Errorf("BaseAddress: expected '%s', got '%s'", tt.expectBase, addr.BaseAddress())
			}
		})
	}
}
